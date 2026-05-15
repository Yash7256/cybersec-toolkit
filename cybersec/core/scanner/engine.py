"""
Async port scanner with Adaptive Concurrency (AIMD).
Supports multiple scan modes: connect, syn, udp, stealth_*, zombie, full
"""
import asyncio
import errno
import ipaddress
import json
import os
import socket
import struct
import time
from datetime import datetime, timezone
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List, Callable, Awaitable, Dict, Any

from cybersec.core.scanner.utils import resolve_target_async, parse_ports


try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    psutil = None


class PortState(str, Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    TIMEOUT = "timeout"
    ERROR = "error"
    UNREACHABLE = "unreachable"
    # Granular failure taxonomy
    REFUSED = "refused"              # ECONNREFUSED — port closed, no listener
    RST = "rst"                      # RST received — port closed or rejected
    HOST_UNREACH = "host_unreach"    # EHOSTUNREACH — no route to host
    NET_UNREACH = "net_unreach"      # ENETUNREACH — network unreachable
    ICMP_REJECT = "icmp_reject"      # ICMP unreachable (via Scapy or fallback)
    EPHEMERAL_EXHAUST = "ephemeral_exhaust"  # EADDRINUSE / EADDRNOTAVAIL
    TIMEOUT_FILTERED = "timeout_filtered"   # no response → likely firewall
from cybersec.core.scanner.analysis.service_detect import ServiceDetector, ServiceDetectionResult
from cybersec.config import settings
from cybersec.core.security.cve_lookup import CVELookup, CVEEntry
from cybersec.core.scanner.analysis.port_analyzer import PortAnalyzer, PortRisk
from cybersec.core.scanner.analysis.os_fingerprint import OSFingerprinter, OSFingerprint
from cybersec.core.networking import AsyncConnectionPool, rst_probe, rst_probe_fallback, SCAPY_AVAILABLE
from cybersec.core.metrics import StressTestMetrics
from cybersec.core.metrics_registry import (
    scan_ports_sec,
    scan_success_rate,
    scan_timeout_rate,
    enrichment_latency,
    enrichment_stage1_backlog,
    enrichment_stage2_backlog,
    enrichment_stage3_backlog,
    dns_resolve_duration,
    connect_latency,
    semaphore_wait_time,
    service_detect_duration,
    cve_lookup_duration,
    risk_analysis_duration,
    fd_usage,
    active_sockets,
)
import logging
import json as json_mod

logger = logging.getLogger(__name__)

# ── Ephemeral port / TIME_WAIT constants ──────────────────────────────
# Linux default range: /proc/sys/net/ipv4/ip_local_port_range
EPHEMERAL_PORT_MIN = 32768
EPHEMERAL_PORT_MAX = 60999
EPHEMERAL_PORT_BUDGET = EPHEMERAL_PORT_MAX - EPHEMERAL_PORT_MIN  # ≈ 28k

# Linux hardcodes TIME_WAIT at 60 seconds (net.ipv4.tcp_fin_timeout)
TCP_TIME_WAIT_SECS = 60

# A single scan should use at most 80 % of the global ephemeral budget
MAX_PORT_BUDGET_FRACTION = 0.8


def _safe_max_concurrency() -> int:
    """Return a safe concurrency ceiling based on the ephemeral-port budget.

    Each TCP connect-scan socket enters TIME_WAIT for ~60 s after close.
    If we can recycle ports every 60 s, the safe steady-state concurrency
    is (budget * fraction) / (time_wait / pps), but since we batch *then*
    wait, the simpler bound is: never exceed budget * fraction.
    """
    return int(EPHEMERAL_PORT_BUDGET * MAX_PORT_BUDGET_FRACTION)


def _safe_value(val, default=None):
    """Safely get value, handling None."""
    return val if val is not None else default


@dataclass
class PortResult:
    port: int
    protocol: str
    state: str
    service: Optional[ServiceDetectionResult] = None
    os_fingerprint: Optional[OSFingerprint] = None
    cves: List[CVEEntry] = field(default_factory=list)
    risk: Optional[PortRisk] = None
    banner: Optional[str] = None
    latency_ms: Optional[float] = None
    tls_info: Optional[Any] = None
    syn_ack_data: Optional[Dict[str, Any]] = None

@dataclass
class ScanReport:
    target: str
    ip: str
    total_ports_scanned: int
    open_ports: List[PortResult]
    os_fingerprint: Optional[OSFingerprint]
    scan_duration: float
    started_at: datetime
    completed_at: datetime
    avg_latency_ms: Optional[float] = None
    peak_concurrency: int = 0
    scan_mode: str = "connect"
    is_ipv6: bool = False
    metrics: Optional[Dict[str, Any]] = None  # ADDED: stress test metrics
    
    def to_json(self) -> str:
        """Convert scan report to JSON format."""
        return json.dumps(self.to_dict(), indent=2, default=str)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert scan report to dictionary format."""
        result = {
            "target": self.target,
            "ip": self.ip,
            "scan_time": {
                "started_at": self.started_at.isoformat(),
                "completed_at": self.completed_at.isoformat(),
                "duration_seconds": round(self.scan_duration, 2),
                "scan_mode": self.scan_mode
            },
            "scan_stats": {
                "total_ports_scanned": self.total_ports_scanned,
                "open_ports_count": len(self.open_ports),
                "avg_latency_ms": self.avg_latency_ms,
                "peak_concurrency": self.peak_concurrency
            },
            "ports": [self._port_to_dict(port) for port in self.open_ports],
            "os_fingerprint": {
                "os_name": self.os_fingerprint.os_name,
                "confidence": self.os_fingerprint.confidence,
                "method": self.os_fingerprint.method
            } if self.os_fingerprint else None
        }
        # ADDED: Include stress test metrics
        if self.metrics:
            result["metrics"] = self.metrics
        return result
    
    def _port_to_dict(self, port: PortResult) -> Dict[str, Any]:
        """Convert PortResult to dictionary."""
        return {
            "port": port.port,
            "protocol": port.protocol,
            "state": port.state,
            "service": {
                "name": port.service.service_name if port.service else "unknown",
                "version": port.service.service_version if port.service else None,
                "banner": port.service.banner_snippet if port.service else None,
                "detection_method": port.service.detection_method if port.service else "unknown",
                "confidence": port.service.confidence if port.service else 0.0,
                "banner_snippet": port.service.banner_snippet if port.service else ""
            },
            "cves": [{
                "id": cve.id,
                "severity": cve.severity,
                "cvss_score": cve.cvss_score,
                "description": cve.description
            } for cve in (port.cves or [])],
            "risk": {
                "risk_level": port.risk.risk_level if port.risk else "UNKNOWN",
                "risk_score": port.risk.risk_score if port.risk else 0.0
            },
            "banner": port.banner,
            "latency_ms": port.latency_ms
        }
    
    def save_to_file(self, format_type: str = "json") -> str:
        """Save scan report to a file with auto-generated filename.
        
        Args:
            format_type: Output format ("json" or "csv")
            
        Returns:
            str: Path to the saved file
        """
        import os
        from datetime import datetime
        
        # Create scan_results directory if it doesn't exist
        os.makedirs("scan_results", exist_ok=True)
        
        # Generate filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = self.target.replace(":", "_").replace("/", "_")
        
        if format_type.lower() == "json":
            filename = f"scan_{safe_target}_{timestamp}.json"
            filepath = os.path.join("scan_results", filename)
            
            with open(filepath, 'w') as f:
                f.write(self.to_json())
                
        elif format_type.lower() == "csv":
            filename = f"scan_{safe_target}_{timestamp}.csv"
            filepath = os.path.join("scan_results", filename)
            
            with open(filepath, 'w') as f:
                f.write(self.to_csv())
                
        else:
            raise ValueError(f"Unsupported format: {format_type}")
        
        return filepath
    
    def to_csv(self) -> str:
        """Convert scan report to CSV format."""
        import csv
        import io
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Header
        writer.writerow(["target", "port", "protocol", "state", "service", "version", "banner", "risk_level", "risk_score", "cve_count"])
        
        # Data rows
        for port in self.open_ports:
            cve_count = len(port.cves) if port.cves else 0
            writer.writerow([
                self.target,
                port.port,
                port.protocol or "tcp",
                port.state or "open",
                port.service.service_name if port.service else "unknown",
                port.service.service_version if port.service else "",
                port.banner or "",
                port.risk.risk_level if port.risk else "UNKNOWN",
                port.risk.risk_score if port.risk else 0.0,
                cve_count
            ])
        
        return output.getvalue()


class SystemAdaptiveConcurrency:
    """
    System-aware adaptive concurrency controller.

    Dynamically adjusts concurrency based on:
      - CPU load (psutil, falls back to 0)
      - Open file descriptor count vs system limit
      - Timeout rate from each batch
      - Average latency from each batch

    Safe concurrency = max * cpu_factor * fd_factor * timeout_factor * latency_factor
    Each factor is 0.0–1.0 and multiplicatively reduces from the configured max.
    """
    def __init__(self, min_workers: int = 20, max_workers: int = 1000, initial_workers: int = 200):
        ephem_limit = _safe_max_concurrency()
        max_workers = min(max_workers, ephem_limit)
        initial_workers = min(initial_workers, ephem_limit)
        self.current = initial_workers
        self.min = min_workers
        self.max = max_workers
        self.peak = initial_workers
        self._batch_count = 0
        self._timeout_rate = 0.0
        self._avg_latency_ms = 0.0

        self._process = None
        if PSUTIL_AVAILABLE:
            try:
                self._process = psutil.Process(os.getpid())
                psutil.cpu_percent(interval=0)
            except Exception:
                self._process = None

    # ── helpers ──────────────────────────────────────────────────────────

    def _get_cpu_load(self) -> float:
        if not self._process:
            return 0.0
        try:
            return self._process.cpu_percent(interval=0) / 100.0
        except Exception:
            return 0.0

    def _get_fd_count(self) -> int:
        try:
            return len(os.listdir(f"/proc/{os.getpid()}/fd"))
        except Exception:
            return 0

    def _get_fd_limit(self) -> int:
        try:
            import resource
            soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
            return soft or 4096
        except Exception:
            return 4096

    # ── factor computation ───────────────────────────────────────────────

    def _cpu_factor(self) -> float:
        cpu = self._get_cpu_load()
        return max(0.2, 1.0 - cpu)                   # 1.0 @ 0% cpu, 0.2 @ 80%+

    def _fd_factor(self) -> float:
        count = self._get_fd_count()
        limit = self._get_fd_limit()
        ratio = count / max(limit, 1)
        return max(0.1, 1.0 - ratio * 2)             # 1.0 @ 0%, 0.1 @ 45%+

    def _timeout_factor(self) -> float:
        return max(0.1, 1.0 - self._timeout_rate * 3)  # 1.0 @ 0%, 0.1 @ 30%+

    def _latency_factor(self) -> float:
        if self._avg_latency_ms <= 0:
            return 1.0
        return max(0.2, 1.0 - self._avg_latency_ms / 5000.0)  # 1.0 @ 0ms, 0.2 @ 4s+

    def _evloop_factor(self) -> float:
        """Reduce concurrency when the event loop is lagging."""
        try:
            from cybersec.core.metrics_registry import event_loop_lag_ms
            lag = event_loop_lag_ms().get()
            if lag > 500:
                return 0.1   # severely stalled → drop to minimum
            if lag > 100:
                return 0.5   # stalled → halve concurrency
            return 1.0       # healthy
        except Exception:
            return 1.0

    # ── public API ───────────────────────────────────────────────────────

    async def adjust(self, batch_stats: dict) -> None:
        """Adjust concurrency after a batch completes."""
        self._batch_count += 1

        tr = batch_stats.get("timeout_rate", self._timeout_rate)
        al = batch_stats.get("avg_latency_ms", self._avg_latency_ms)

        if self._batch_count > 1:
            self._timeout_rate = self._timeout_rate * 0.3 + tr * 0.7
            self._avg_latency_ms = self._avg_latency_ms * 0.5 + al * 0.5
        else:
            self._timeout_rate = tr
            self._avg_latency_ms = al

        combined = self._cpu_factor() * self._fd_factor() * self._timeout_factor() * self._latency_factor() * self._evloop_factor()
        safe = int(self.max * combined)
        self.current = max(self.min, min(self.max, safe))
        if self.current > self.peak:
            self.peak = self.current

    def get_semaphore(self) -> asyncio.Semaphore:
        return asyncio.Semaphore(self.current)

    @property
    def semaphore_value(self) -> int:
        return self.current


class AsyncPortScanner:
    """High-performance async port scanner with advanced features.
    
    The AsyncPortScanner provides comprehensive network scanning capabilities including:
    - Multiple scan modes (TCP connect, SYN, UDP, stealth scans)
    - Rate limiting with token bucket algorithm
    - Adaptive concurrency control with AIMD
    - Connection pooling for improved performance
    - Service detection and OS fingerprinting
    - CVE lookup and risk assessment
    - Real-time progress tracking
    
    Attributes:
        timeout: Connection timeout in seconds for each port probe
        enable_connection_pool: Whether to reuse TCP connections
        scan_id: Unique identifier for this scan instance
        service_detector: Service detection engine
        cve_lookup: CVE vulnerability database lookup
        port_analyzer: Port risk assessment engine
        os_fingerprinter: OS fingerprinting engine
        _connection_pools: Per-host connection pools for reuse
    
    Example:
        ```python
        scanner = AsyncPortScanner(
            timeout=3.0,
            enable_connection_pool=True,
            rate_preset="normal",
            rate_pps=1000.0
        )
        
        report = await scanner.scan("192.168.1.1", "1-1000")
        print(f"Found {len(report.open_ports)} open ports")
        ```
    """
    
    def __init__(self, timeout: Optional[float] = None, enable_connection_pool: bool = True, scan_id: Optional[str] = None, 
                 rate_preset: str = "normal", rate_pps: Optional[float] = None, retries: int = 0):
        """Initialize the AsyncPortScanner.
        
        Args:
            timeout: Connection timeout in seconds for each port probe
            enable_connection_pool: Whether to use TCP connection pooling
            scan_id: Optional unique identifier for this scan
            rate_preset: Rate limiting preset ("stealth", "normal", "aggressive")
            rate_pps: Custom rate in packets per second (overrides preset)
            retries: Number of retry attempts on timeout/connection failure
        """
        self.timeout = timeout or settings.SCAN_TIMEOUT
        self.enable_connection_pool = enable_connection_pool
        self.scan_id = scan_id or f"scan_{int(time.time())}"
        self.retries = retries

        # Dynamic timeout via RTT EMA
        self._rtt_ema: float = self.timeout
        self._rtt_alpha: float = 0.3
        
        # Initialize rate limiter
        from cybersec.core.security.rate_limiter import RateLimiter
        self.rate_limiter = RateLimiter(rate_preset, rate_pps)
        self.service_detector = ServiceDetector()
        self.cve_lookup = CVELookup()
        self.port_analyzer = PortAnalyzer()
        self.os_fingerprinter = OSFingerprinter()
        self._syn_scanner = None
        self._udp_scanner = None
        self._stealth_scanner = None
        self._zombie_scanner = None
        self._tls_fingerprinter = None
        self._connection_pools = {}  # {host: AsyncConnectionPool}
        self._adaptive_cc = SystemAdaptiveConcurrency()
        logger.info(
            "Adaptive concurrency initialised: max=%d, ephemeral-port ceiling=%d",
            self._adaptive_cc.max, _safe_max_concurrency(),
        )
        
        # ADDED: Stress test metrics
        self._metrics = StressTestMetrics()
    
    @property
    def metrics(self) -> StressTestMetrics:
        """Get stress test metrics instance."""
        return self._metrics

    @property
    def _effective_timeout(self) -> float:
        """Dynamic connect timeout based on measured RTT.

        timeout = clamp(rtt_ema * 4, min=0.5, max=5.0)

        Fast hosts get fast timeouts; slow hosts don't waste unlimited time.
        """
        return max(0.5, min(5.0, self._rtt_ema * 4))

    def _update_rtt(self, latency_ms: float) -> None:
        """Update the RTT EMA with a new sample."""
        if latency_ms > 0:
            self._rtt_ema = self._rtt_alpha * (latency_ms / 1000) + (1 - self._rtt_alpha) * self._rtt_ema

    async def _scan_with_retry(self, ip: str, port: int) -> PortResult:
        """Scan a port with retry logic."""
        last_result = None
        
        for attempt in range(self.retries + 1):
            result = await self._scan_port_simple(ip, port)
            last_result = result
            
            if result.state == PortState.OPEN.value:
                return result
            
            if attempt < self.retries:
                await asyncio.sleep(0.1 * (attempt + 1))
        
        return last_result or PortResult(
            port=port,
            protocol="tcp",
            state=PortState.FILTERED.value,
            latency_ms=self.timeout * 1000
        )

    def _get_syn_scanner(self):
        if self._syn_scanner is None:
            try:
                from cybersec.core.scanner.scans.syn import SYNScanner
                self._syn_scanner = SYNScanner(timeout=self.timeout)
            except (ImportError, PermissionError):
                self._syn_scanner = None
        return self._syn_scanner

    def _get_udp_scanner(self):
        if self._udp_scanner is None:
            try:
                from cybersec.core.scanner.scans.udp import UDPScanner
                self._udp_scanner = UDPScanner(timeout=self.timeout)
            except (ImportError, PermissionError):
                self._udp_scanner = None
        return self._udp_scanner

    def _get_stealth_scanner(self):
        if self._stealth_scanner is None:
            try:
                from cybersec.core.scanner.scans.stealth import StealthScanner
                self._stealth_scanner = StealthScanner(timeout=self.timeout, rate_pps=self.rate_limiter.get_rate_pps())
            except (ImportError, PermissionError):
                self._stealth_scanner = None
        return self._stealth_scanner

    def _get_zombie_scanner(self, zombie_ip: str):
        try:
            from cybersec.core.scanner.scans.zombie import ZombieScanner
            return ZombieScanner(zombie_ip=zombie_ip, timeout=self.timeout)
        except (ImportError, PermissionError):
            return None

    def _get_tls_fingerprinter(self):
        if self._tls_fingerprinter is None:
            try:
                from cybersec.core.scanner.analysis.tls_fingerprint import TLSFingerprinter
                self._tls_fingerprinter = TLSFingerprinter(timeout=self.timeout)
            except ImportError:
                self._tls_fingerprinter = None
        return self._tls_fingerprinter

    def _get_connection_pool(self, host: str) -> AsyncConnectionPool:
        """Get or create connection pool for a host."""
        if not self.enable_connection_pool:
            return None
            
        if host not in self._connection_pools:
            pool_size = max(50, self._adaptive_cc.semaphore_value)
            self._connection_pools[host] = AsyncConnectionPool(
                max_size=pool_size, 
                max_idle_time=30.0
            )
        return self._connection_pools[host]

    async def _cleanup_pools(self):
        """Cleanup all connection pools."""
        cleanup_tasks = []
        for pool in self._connection_pools.values():
            cleanup_tasks.append(pool.cleanup())
        
        if cleanup_tasks:
            await asyncio.gather(*cleanup_tasks, return_exceptions=True)
        
        self._connection_pools.clear()

    async def _fingerprint_os(self, ip: str, valid_ports: list,
                               open_ports_results: list) -> Optional[OSFingerprint]:
        """Run OS fingerprinting (runs in executor — Scapy is sync)."""
        try:
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(
                None, self.os_fingerprinter.fingerprint_active, ip, valid_ports
            )
        except PermissionError:
            logger.warning("Active OS fingerprinting requires root — using banner fallback")
        except Exception:
            logger.warning("Active OS fingerprinting failed — using banner fallback")

        banners = [p.banner for p in open_ports_results if p.banner]
        services = [p.service for p in open_ports_results]
        return self.os_fingerprinter.fingerprint(banners, valid_ports, services)

    def _is_ipv6(self, target: str) -> bool:
        try:
            socket.inet_pton(socket.AF_INET6, target)
            return True
        except socket.error:
            return False

    async def _rst_probe(self, ip: str, port: int) -> bool:
        if not SCAPY_AVAILABLE:
            return await self._rst_probe_fallback(ip, port)
        return await rst_probe(ip, port)
    
    async def _rst_probe_fallback(self, ip: str, port: int) -> bool:
        return await rst_probe_fallback(ip, port)

    @staticmethod
    def _create_optimized_socket() -> socket.socket:
        """Create a TCP socket with SO_REUSEADDR and SO_LINGER to reduce
        TIME_WAIT pressure and avoid EADDRINUSE on rapid reconnect."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            # Enable quick recycling of TIME_WAIT sockets (BSD/MacOS)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except AttributeError:
            pass
        linger = struct.pack("ii", 1, 0)  # l_onoff=1, l_linger=0 → abortive close
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, linger)
        except OSError:
            pass
        sock.settimeout(None)  # we use asyncio timeouts
        return sock

    async def _connect_with_reuse(self, ip: str, port: int) -> tuple:
        """Open a TCP connection using a socket with SO_REUSEADDR + SO_LINGER
        so the kernel recycles the ephemeral port faster after close."""
        loop = asyncio.get_running_loop()
        sock = self._create_optimized_socket()
        try:
            await asyncio.wait_for(
                loop.sock_connect(sock, (ip, port)),
                timeout=self._effective_timeout,
            )
            reader = asyncio.StreamReader()
            protocol = asyncio.StreamReaderProtocol(reader)
            transport, _ = await loop.create_connection(
                lambda: protocol, sock=sock,
            )
            writer = asyncio.StreamWriter(transport, protocol, reader, loop)
            return reader, writer
        except BaseException:
            sock.close()
            raise

    async def _scan_port_simple(
        self,
        ip: str,
        port: int,
    ) -> PortResult:
        _sem_t0 = time.monotonic()
        async with self._adaptive_cc.get_semaphore():
            semaphore_wait_time().observe(time.monotonic() - _sem_t0)
            await self.rate_limiter.throttle()

            t_start = time.monotonic()
            state = "closed"
            latency_ms = None
            connection_id = None

            self._metrics.increment_total_ports_scanned()

            try:
                reader, writer = await self._connect_with_reuse(ip, port)

                latency_ms = (time.monotonic() - t_start) * 1000
                connect_latency().observe(latency_ms / 1000)
                state = PortState.OPEN.value
                self._update_rtt(latency_ms)

                self._metrics.increment_successful_connections()
                self._metrics.increment_port_state("open")

                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

            except asyncio.TimeoutError:
                state = PortState.TIMEOUT_FILTERED.value
                latency_ms = self._effective_timeout * 1000
                self._metrics.increment_timeouts()
                self._metrics.increment_port_state(state)
            except ConnectionRefusedError:
                state = PortState.REFUSED.value
                latency_ms = self._effective_timeout * 1000
                self._metrics.increment_failed_connections()
                self._metrics.increment_port_state(state)
            except OSError as e:
                err = e.errno
                if err in (errno.ECONNRESET,):
                    state = PortState.RST.value
                elif err == errno.ENETUNREACH:
                    state = PortState.NET_UNREACH.value
                elif err in (errno.EHOSTUNREACH, 113):
                    state = PortState.HOST_UNREACH.value
                elif err in (errno.EADDRINUSE, errno.EADDRNOTAVAIL, errno.EAGAIN):
                    state = PortState.EPHEMERAL_EXHAUST.value
                    logger.warning(
                        "Ephemeral port exhaustion on %s:%d (errno=%s) — "
                        "reduce concurrency or use --scan-mode syn",
                        ip, port, errno.errorcode.get(err, str(err)),
                    )
                elif err == errno.ECONNREFUSED:
                    state = PortState.REFUSED.value
                elif err in (errno.ETIMEDOUT, errno.EHOSTDOWN, errno.ENODATA):
                    state = PortState.TIMEOUT_FILTERED.value
                else:
                    state = PortState.FILTERED.value
                    logger.debug("Unclassified OSError on %s:%d errno=%s",
                                 ip, port, errno.errorcode.get(err, str(err)))
                self._metrics.increment_port_state(state)
                self._metrics.increment_failed_connections()
                latency_ms = self._effective_timeout * 1000
            except Exception:
                state = PortState.ERROR.value
                latency_ms = self._effective_timeout * 1000
                self._metrics.increment_failed_connections()
                self._metrics.increment_port_state(state)

            return PortResult(
                port=port,
                protocol="tcp",
                state=state,
                latency_ms=latency_ms,
                syn_ack_data=None
            )

    async def _stage_service_detect(
        self,
        ip: str,
        port_res: PortResult,
        banners: List[str],
        run_tls: bool = False
    ) -> PortResult:
        """Stage 1: Service detection + banner grabbing + TLS analysis."""
        _t0 = time.monotonic()
        try:
            if settings.ENABLE_SERVICE_DETECTION:
                service_info = await self.service_detector.detect(ip, port_res.port, timeout=self.timeout)
                port_res.service = service_info
                if service_info and service_info.banner_snippet:
                    port_res.banner = service_info.banner_snippet
                    banners.append(service_info.banner_snippet)
                else:
                    port_res.banner = None
            else:
                port_res.service = None
                port_res.banner = None
        except Exception as e:
            logger.error(f"Service detection failed for port {port_res.port}: {e}")
            port_res.service = None
            port_res.banner = None

        # Extract TLS info from service detection result
        if port_res.service and port_res.service.tls_version:
            port_res.tls_info = {
                "version": port_res.service.tls_version,
                "alpn": port_res.service.alpn,
                "subject": port_res.service.cert_subject,
                "issuer": port_res.service.cert_issuer,
            }
        elif run_tls and port_res.port in [443, 8443]:
            tls_fp = self._get_tls_fingerprinter()
            if tls_fp:
                try:
                    port_res.tls_info = await tls_fp.get_tls_info(ip, port_res.port)
                except Exception:
                    pass

        service_detect_duration().observe(time.monotonic() - _t0)
        return port_res

    async def _stage_cve_lookup(self, port_res: PortResult) -> PortResult:
        """Stage 2: CVE lookup (network I/O to NVD API)."""
        _t0 = time.monotonic()
        service_name = port_res.service.service_name if port_res.service else "unknown"
        service_version = port_res.service.service_version if port_res.service else None
        try:
            port_res.cves = await self.cve_lookup.lookup(service_name, service_version)
        except Exception as e:
            logger.error(f"CVE lookup failed for {service_name}: {e}")
            port_res.cves = []
        cve_lookup_duration().observe(time.monotonic() - _t0)
        return port_res

    async def _stage_risk_analysis(self, port_res: PortResult) -> PortResult:
        """Stage 3: Risk analysis (fast, local computation)."""
        _t0 = time.monotonic()
        try:
            port_res.risk = self.port_analyzer.analyze(port_res.port, port_res.cves)
        except Exception as e:
            logger.error(f"Risk analysis failed for port {port_res.port}: {e}")
            port_res.risk = None
        risk_analysis_duration().observe(time.monotonic() - _t0)
        return port_res

    async def _run_enrichment_pipeline(
        self,
        ip: str,
        scan_callback: Optional[Callable[[PortResult], Awaitable[None]]] = None,
        run_tls: bool = False,
        service_workers: int = 20,
        cve_workers: int = 10,
        risk_workers: int = 5,
    ) -> None:
        """
        Multi-stage enrichment pipeline.

        Stage 1 (service detect)   → queue1 → service_workers
        Stage 2 (CVE lookup)       → queue2 → cve_workers
        Stage 3 (risk analysis)    → queue3 → risk_workers → results

        Each stage runs independently so slow CVE lookups on port X
        don't block service detection on port Y.
        """
        queue1: asyncio.Queue = asyncio.Queue(maxsize=1000)
        queue2: asyncio.Queue = asyncio.Queue(maxsize=1000)
        queue3: asyncio.Queue = asyncio.Queue(maxsize=1000)
        banners: List[str] = []

        PUT_TIMEOUT = 5
        GET_TIMEOUT = 30

        # ── Stage 3 → results (local aggregation, batch merge) ──────
        stage3_buffers: list[list] = [[] for _ in range(risk_workers)]

        async def stage3_worker(worker_idx: int) -> None:
            buf = stage3_buffers[worker_idx]
            while True:
                try:
                    port_res = await asyncio.wait_for(queue3.get(), timeout=GET_TIMEOUT)
                except asyncio.TimeoutError:
                    logger.warning("Stage3 worker %d: queue3.get timed out", worker_idx)
                    continue
                try:
                    if port_res is None:
                        return
                    enriched = await self._stage_risk_analysis(port_res)
                    buf.append(enriched)
                    if scan_callback:
                        try:
                            await scan_callback(enriched)
                        except Exception as e:
                            logger.error(f"Callback failed for port {enriched.port}: {e}")
                finally:
                    queue3.task_done()

        # ── Stage 2 → queue3 ─────────────────────────────────────────
        async def stage2_worker() -> None:
            while True:
                try:
                    port_res = await asyncio.wait_for(queue2.get(), timeout=GET_TIMEOUT)
                except asyncio.TimeoutError:
                    logger.warning("Stage2 worker: queue2.get timed out")
                    continue
                try:
                    if port_res is None:
                        return
                    enriched = await self._stage_cve_lookup(port_res)
                    await asyncio.wait_for(queue3.put(enriched), timeout=PUT_TIMEOUT)
                finally:
                    queue2.task_done()

        # ── Stage 1 → queue2 (local banner aggregation) ─────────────
        stage1_banners: list[list] = [[] for _ in range(service_workers)]

        async def stage1_worker(worker_idx: int) -> None:
            buf = stage1_banners[worker_idx]
            while True:
                try:
                    port_res = await asyncio.wait_for(queue1.get(), timeout=GET_TIMEOUT)
                except asyncio.TimeoutError:
                    logger.warning("Stage1 worker %d: queue1.get timed out", worker_idx)
                    continue
                try:
                    if port_res is None:
                        return
                    t0 = time.monotonic()
                    enriched = await self._stage_service_detect(ip, port_res, buf, run_tls=run_tls)
                    enrichment_latency().observe(time.monotonic() - t0)
                    await asyncio.wait_for(queue2.put(enriched), timeout=PUT_TIMEOUT)
                finally:
                    queue1.task_done()

        s1 = [asyncio.create_task(stage1_worker(i)) for i in range(service_workers)]
        s2 = [asyncio.create_task(stage2_worker()) for _ in range(cve_workers)]
        s3 = [asyncio.create_task(stage3_worker(i)) for i in range(risk_workers)]

        for port_res in open_ports_results:
            await asyncio.wait_for(queue1.put(port_res), timeout=PUT_TIMEOUT)

        enrichment_stage1_backlog().set(queue1.qsize())
        enrichment_stage2_backlog().set(queue2.qsize())
        enrichment_stage3_backlog().set(queue3.qsize())

        await queue1.join()
        enrichment_stage1_backlog().set(0)
        for _ in s1:
            await asyncio.wait_for(queue1.put(None), timeout=PUT_TIMEOUT)
        await asyncio.gather(*s1, return_exceptions=True)
        banners[:] = [b for buf in stage1_banners for b in buf]

        enrichment_stage2_backlog().set(queue2.qsize())
        await queue2.join()
        enrichment_stage2_backlog().set(0)
        for _ in s2:
            await asyncio.wait_for(queue2.put(None), timeout=PUT_TIMEOUT)
        await asyncio.gather(*s2, return_exceptions=True)

        enrichment_stage3_backlog().set(queue3.qsize())
        await queue3.join()
        enrichment_stage3_backlog().set(0)
        for _ in s3:
            await asyncio.wait_for(queue3.put(None), timeout=PUT_TIMEOUT)
        await asyncio.gather(*s3, return_exceptions=True)

        # Batch merge: no per-item contention on shared lists
        open_ports_results[:] = [p for buf in stage3_buffers for p in buf]
        valid_ports.extend(p.port for p in open_ports_results)

        open_ports_results.sort(key=lambda p: port_order.get(p.port, len(port_order)))

    async def enrich_results(
        self,
        ip: str,
        open_ports_results: List[PortResult],
        valid_ports: List[int],
        scan_callback: Optional[Callable[[PortResult], Awaitable[None]]] = None,
        scan_mode: str = "connect",
    ) -> List[PortResult]:
        """Run enrichment pipeline on already-discovered open ports.

        This can be called independently after scan() returns, enabling
        the scan to return immediately and enrichment to continue in the
        background.

        Returns the enriched port list (sorted by port number).
        """
        if not open_ports_results:
            return open_ports_results

        await self._run_enrichment_pipeline(
            ip,
            scan_callback=scan_callback,
            run_tls=(scan_mode == "full"),
        )

        return open_ports_results

    async def scan(
        self,
        target: str,
        port_range: str = "common",
        scan_callback: Optional[Callable[[PortResult], Awaitable[None]]] = None,
        resolved_ip: Optional[str] = None,
        scan_mode: str = "connect",
        zombie_ip: Optional[str] = None,
        ip_version: str = "auto",
        enrich: bool = True,
    ) -> ScanReport:
        """Scan a target for open ports with comprehensive analysis.
        
        This is the main scanning method that supports multiple scan modes and
        provides detailed port analysis including service detection, CVE lookup,
        and risk assessment.
        
        Args:
            target: Target to scan (IP address, hostname, or domain)
            port_range: Port specification. Options:
                - "common": Common ports (21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995)
                - "top1000": Top 1000 most common ports
                - "all": All 65535 ports
                - "1-1000": Custom range
                - "80,443,8080": Comma-separated ports
            scan_callback: Optional callback function for real-time progress updates
            resolved_ip: Pre-resolved IP address (skips DNS resolution)
            scan_mode: Scanning technique. Options:
                - "connect": TCP connect scan (default)
                - "syn": SYN stealth scan (requires root)
                - "udp": UDP scan
                - "stealth_fin": FIN stealth scan
                - "stealth_null": NULL stealth scan
                - "stealth_xmas": XMAS stealth scan
                - "stealth_ack": ACK stealth scan
                - "zombie": Idle scan (requires zombie_ip)
            zombie_ip: Zombie host IP for idle scan mode
        
        Returns:
            ScanReport: Comprehensive scan results including:
                - Open ports with service information
                - CVE vulnerabilities found
                - Risk assessments
                - OS fingerprinting results
                - Performance metrics
        
        Raises:
            ValueError: If target cannot be resolved
            PermissionError: If privileged scan mode requires root
            OSError: If network issues prevent scanning
        
        Example:
            ```python
            scanner = AsyncPortScanner()
            
            # Basic scan
            report = await scanner.scan("192.168.1.1", "1-1000")
            print(f"Found {len(report.open_ports)} open ports")
            
            # With progress callback
            async def progress_callback(port_result):
                print(f"Port {port_result.port}: {port_result.state}")
            
            report = await scanner.scan(
                "192.168.1.1", 
                "1-1000", 
                scan_callback=progress_callback
            )
            ```
        """
        ports = parse_ports(port_range)
        is_ipv6 = self._is_ipv6(target)
        
        ip = resolved_ip
        if not ip:
            family_map = {"ipv4": socket.AF_INET, "ipv6": socket.AF_INET6, "auto": 0}
            family = family_map.get(ip_version, 0)
            try:
                _dns_t0 = time.monotonic()
                ip = await resolve_target_async(target, family=family)
                dns_resolve_duration().observe(time.monotonic() - _dns_t0)
                if family == socket.AF_INET6 or ":" in ip:
                    is_ipv6 = True
            except Exception:
                raise ValueError(
                    f"Could not resolve target: {target} "
                    f"(ip_version={ip_version})"
                )

        started_at = datetime.now(timezone.utc)
        open_ports_results: List[PortResult] = []
        valid_ports: List[int] = []
        latencies: List[float] = []
        
        # ADDED: Reset and start metrics tracking
        self._metrics.reset()
        self._metrics.start_scan()

        if scan_mode == "syn":
            syn_scanner = self._get_syn_scanner()
            if syn_scanner and syn_scanner.is_available():
                syn_results = await syn_scanner.scan(ip, ports)
                for syn_res in syn_results:
                    if syn_res.state == "open":
                        port_result = PortResult(
                            port=syn_res.port,
                            protocol="tcp",
                            state="open",
                            syn_ack_data={
                                "ttl": syn_res.ttl,
                                "window_size": syn_res.window_size,
                                "tcp_options": syn_res.tcp_options,
                                "ip_id": syn_res.ip_id,
                                "df_flag": syn_res.df_flag
                            }
                        )
                        open_ports_results.append(port_result)
                        if syn_res.latency_ms:
                            latencies.append(syn_res.latency_ms)
            else:
                scan_mode = "connect"

        elif scan_mode == "udp":
            udp_scanner = self._get_udp_scanner()
            if udp_scanner and udp_scanner.is_available():
                udp_results = await udp_scanner.scan(ip, ports)
                for udp_res in udp_results:
                    port_result = PortResult(
                        port=udp_res.port,
                        protocol="udp",
                        state=udp_res.state,
                        latency_ms=udp_res.latency_ms
                    )
                    open_ports_results.append(port_result)
            else:
                scan_mode = "connect"

        elif scan_mode in ["stealth_fin", "stealth_null", "stealth_xmas", "stealth_ack"]:
            stealth_scanner = self._get_stealth_scanner()
            scan_type = scan_mode.replace("stealth_", "")
            if stealth_scanner and stealth_scanner.is_available():
                stealth_results = await stealth_scanner.scan(ip, ports, scan_type=scan_type)
                for stealth_res in stealth_results:
                    if stealth_res.state in ["open", "open|filtered", "unfiltered"]:
                        port_result = PortResult(
                            port=stealth_res.port,
                            protocol="tcp",
                            state=stealth_res.state
                        )
                        open_ports_results.append(port_result)
            else:
                scan_mode = "connect"

        elif scan_mode == "ack":
            stealth_scanner = self._get_stealth_scanner()
            if stealth_scanner and stealth_scanner.is_available():
                ack_results = await stealth_scanner.scan(ip, ports, scan_type="ack")
                for ack_res in ack_results:
                    if ack_res.state in ("unfiltered", "filtered"):
                        port_result = PortResult(
                            port=ack_res.port,
                            protocol="tcp",
                            state=ack_res.state
                        )
                        open_ports_results.append(port_result)
            else:
                scan_mode = "connect"

        elif scan_mode == "zombie":
            if not zombie_ip:
                raise ValueError("zombie_ip required for zombie scan mode")
            zombie_scanner = self._get_zombie_scanner(zombie_ip)
            if zombie_scanner and zombie_scanner.is_available():
                zombie_results = await zombie_scanner.scan(ip, ports)
                for zombie_res in zombie_results:
                    port_result = PortResult(
                        port=zombie_res.target_port,
                        protocol="tcp",
                        state=zombie_res.state
                    )
                    open_ports_results.append(port_result)
            else:
                scan_mode = "connect"

        if scan_mode == "connect" or scan_mode == "port" or scan_mode == "full":
            if len(ports) > _safe_max_concurrency():
                logger.warning(
                    "TCP connect scan on %d ports with concurrency %d — "
                    "may exhaust ephemeral port budget (%d). "
                    "Use --scan-mode syn for large scans.",
                    len(ports), self._adaptive_cc.semaphore_value,
                    _safe_max_concurrency(),
                )
            port_order = {port: idx for idx, port in enumerate(ports)}
            open_ports_results.clear()

            # ── Worker pool: bounded queue + fixed workers ──────────────
            MAX_WORKERS = self._adaptive_cc.semaphore_value
            work_queue: asyncio.Queue = asyncio.Queue(maxsize=MAX_WORKERS * 2)

            for port in ports:
                await work_queue.put(port)

            _scan_t0 = time.monotonic()
            _adjust_interval = 50
            _adjust_count = 0

            # Shared counters for rolling adjustment
            _window_timeouts = 0
            _window_total = 0
            _window_latencies: list[float] = []
            _stats_lock = asyncio.Lock()

            async def _scan_worker() -> None:
                nonlocal _adjust_count, _window_timeouts, _window_total
                while True:
                    port = await work_queue.get()
                    try:
                        if port is None:
                            return
                        result = await self._scan_with_retry(ip, port)
                        if result.latency_ms is not None:
                            latencies.append(result.latency_ms)
                        if result.state == "open":
                            open_ports_results.append(result)

                        # Aggregate into rolling window
                        async with _stats_lock:
                            _adjust_count += 1
                            _window_total += 1
                            if result.state == "timeout":
                                _window_timeouts += 1
                            if result.latency_ms is not None:
                                _window_latencies.append(result.latency_ms)

                            # Adjust every _adjust_interval ports
                            if _window_total >= _adjust_interval:
                                tr = _window_timeouts / max(_window_total, 1)
                                avg_lat = (sum(_window_latencies) / max(len(_window_latencies), 1)
                                           if _window_latencies else 0)
                                await self._adaptive_cc.adjust({
                                    "timeout_rate": tr,
                                    "avg_latency_ms": avg_lat,
                                })
                                scan_timeout_rate().set(tr * 100)
                                elapsed = time.monotonic() - _scan_t0
                                if elapsed > 0:
                                    scan_ports_sec().set(_adjust_count / elapsed)
                                try:
                                    fd_usage().set(len(os.listdir(f"/proc/{os.getpid()}/fd")))
                                except Exception:
                                    pass
                                _window_timeouts = 0
                                _window_total = 0
                                _window_latencies.clear()
                    finally:
                        work_queue.task_done()

            workers = [asyncio.create_task(_scan_worker()) for _ in range(MAX_WORKERS)]

            try:
                await work_queue.join()

                elapsed = time.monotonic() - _scan_t0
                if elapsed > 0:
                    scan_ports_sec().set(len(ports) / elapsed)

            finally:
                for _ in workers:
                    await work_queue.put(None)
                await asyncio.gather(*workers, return_exceptions=True)

        if enrich and open_ports_results:
            await self._run_enrichment_pipeline(
                ip,
                scan_callback=scan_callback,
                run_tls=(scan_mode == "full"),
            )
        
        if scan_mode == "syn":
            for port_res in open_ports_results:
                if port_res.syn_ack_data:
                    self.os_fingerprinter.probe_active(ip, port_res.port)

        os_fingerprint = await self._fingerprint_os(ip, valid_ports, open_ports_results)

        completed_at = datetime.now(timezone.utc)
        scan_duration = (completed_at - started_at).total_seconds()
        avg_latency = sum(latencies) / len(latencies) if latencies else None

        scan_success_rate().set(
            (sum(1 for p in open_ports_results if p.state == "open") / max(len(open_ports_results), 1)) * 100
        )

        logger.info(json_mod.dumps({
            "event": "scan_complete",
            "target": target,
            "ip": ip,
            "scan_mode": scan_mode,
            "duration_s": round(scan_duration, 2),
            "ports_scanned": len(ports),
            "open_ports": len(open_ports_results),
            "peak_concurrency": self._adaptive_cc.peak,
            "rtt_ema_s": round(self._rtt_ema, 3),
            "effective_timeout_s": round(self._effective_timeout, 2),
        }))

        await self._cleanup_pools()
        self._metrics.end_scan()
        stress_metrics = self._metrics.export_metrics()

        return ScanReport(
            target=target,
            ip=ip,
            total_ports_scanned=len(ports),
            open_ports=open_ports_results,
            os_fingerprint=os_fingerprint,
            scan_duration=scan_duration,
            started_at=started_at,
            completed_at=completed_at,
            avg_latency_ms=round(avg_latency, 2) if avg_latency else None,
            peak_concurrency=self._adaptive_cc.peak if scan_mode in ("connect", "port", "full") else 0,
            scan_mode=scan_mode,
            is_ipv6=is_ipv6,
            metrics=stress_metrics,
        )
