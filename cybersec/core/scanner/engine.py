"""
Async port scanner with Adaptive Concurrency (AIMD).
Supports multiple scan modes: connect, syn, udp, stealth_*, zombie, full
"""
import asyncio
import errno
import ipaddress
import json
import socket
import time
from datetime import datetime, timezone
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List, Callable, Awaitable, Dict, Any

from cybersec.core.scanner.utils import resolve_target, parse_ports, resolve_target_ipv6


class PortState(str, Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    TIMEOUT = "timeout"
    ERROR = "error"
    UNREACHABLE = "unreachable"
from cybersec.core.scanner.analysis.service_detect import ServiceDetector, ServiceDetectionResult
from cybersec.config import settings
from cybersec.core.security.cve_lookup import CVELookup, CVEEntry
from cybersec.core.scanner.analysis.port_analyzer import PortAnalyzer, PortRisk
from cybersec.core.scanner.analysis.os_fingerprint import OSFingerprinter, OSFingerprint
from cybersec.core.networking import AsyncConnectionPool, rst_probe, rst_probe_fallback, SCAPY_AVAILABLE
from cybersec.core.metrics import StressTestMetrics
import logging

logger = logging.getLogger(__name__)


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


class AdaptiveConcurrencyController:
    """
    AIMD (Additive Increase, Multiplicative Decrease) concurrency controller.
    Monitors success rates across sliding windows of 50 attempts.
    Reduces concurrency by 50% when success <70%, increases when >90%.
    """
    def __init__(self, min_workers: int = 50, max_workers: int = 500, initial_workers: int = 100):
        self.current = initial_workers
        self.min = min_workers
        self.max = max_workers
        self.peak = initial_workers
        self._window_size = 50
        self._attempts = []
        self._lock = asyncio.Lock()

    async def on_attempt(self, success: bool):
        async with self._lock:
            self._attempts.append(success)
            if len(self._attempts) > self._window_size:
                self._attempts.pop(0)
            
            if len(self._attempts) >= self._window_size:
                success_rate = sum(self._attempts) / len(self._attempts)
                if success_rate < 0.7:
                    # Reduce by 50%
                    self.current = max(self.min, self.current // 2)
                elif success_rate > 0.9:
                    # Increase
                    if self.current < self.max:
                        self.current = min(self.max, self.current + 1)
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
        
        # ADDED: Stress test metrics
        self._metrics = StressTestMetrics()
    
    @property
    def metrics(self) -> StressTestMetrics:
        """Get stress test metrics instance."""
        return self._metrics

    async def _scan_with_retry(
        self,
        ip: str,
        port: int,
        semaphore: asyncio.Semaphore,
        controller: AdaptiveConcurrencyController
    ) -> PortResult:
        """Scan a port with retry logic."""
        last_result = None
        
        for attempt in range(self.retries + 1):
            result = await self._scan_port(ip, port, semaphore, controller)
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

    async def _scan_with_retry(self, ip: str, port: int, semaphore: asyncio.Semaphore) -> PortResult:
        """Scan a port with retry logic."""
        last_result = None
        
        for attempt in range(self.retries + 1):
            result = await self._scan_port_simple(ip, port, semaphore)
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
            # Pool size based on adaptive concurrency
            pool_size = min(100, max(50, int(AdaptiveConcurrencyController().max * 0.3)))
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

    async def _scan_port_simple(
        self,
        ip: str,
        port: int,
        semaphore: asyncio.Semaphore
    ) -> PortResult:
        async with semaphore:
            # Apply rate limiting inside semaphore so throttling doesn't block other concurrent tasks
            await self.rate_limiter.throttle()
            
            t_start = time.monotonic()
            state = "closed"
            latency_ms = None
            connection_reused = False
            connection_id = None
            
            # ADDED: Track this port attempt
            self._metrics.increment_total_ports_scanned()
            
            try:
                # Try to use connection pool first
                pool = self._get_connection_pool(ip)
                
                if pool:
                    connection_info, is_new = await pool.get_connection(ip, port, self.timeout)
                    reader, writer = connection_info[0], connection_info[1]
                    connection_id = connection_info[1]
                    connection_reused = not is_new
                else:
                    # Fallback to regular connection
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(ip, port), timeout=self.timeout
                    )
                
                latency_ms = (time.monotonic() - t_start) * 1000
                state = PortState.OPEN.value
                
                # ADDED: Track successful connection
                self._metrics.increment_successful_connections()
                self._metrics.increment_port_state("open")
                
                # For non-pooled connections, close immediately
                if not pool:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass

            except asyncio.TimeoutError:
                state = PortState.TIMEOUT.value
                latency_ms = self.timeout * 1000
                # ADDED: Track timeout
                self._metrics.increment_timeouts()
                self._metrics.increment_port_state("timeout")
            except ConnectionRefusedError:
                state = PortState.CLOSED.value
                latency_ms = self.timeout * 1000
                self._metrics.increment_failed_connections()
                self._metrics.increment_port_state("closed")
            except OSError as e:
                if e.errno in (errno.EHOSTUNREACH, 113):
                    state = PortState.UNREACHABLE.value
                    self._metrics.increment_port_state("unreachable")
                else:
                    state = PortState.FILTERED.value
                    self._metrics.increment_port_state("filtered")
                latency_ms = self.timeout * 1000
                self._metrics.increment_failed_connections()
            except Exception:
                state = PortState.ERROR.value
                latency_ms = self.timeout * 1000
                # ADDED: Track failed connection (filtered/closed)
                self._metrics.increment_failed_connections()
                self._metrics.increment_port_state("error")
            
            return PortResult(
                port=port,
                protocol="tcp",
                state=state,
                latency_ms=latency_ms,
                syn_ack_data=None
            )

    async def _scan_port(
        self,
        ip: str,
        port: int,
        semaphore: asyncio.Semaphore,
        controller: AdaptiveConcurrencyController
    ) -> PortResult:
        # Apply rate limiting
        await self.rate_limiter.throttle()
        
        async with semaphore:
            t_start = time.monotonic()
            state = "closed"
            latency_ms = None
            connection_reused = False
            connection_id = None
            
            try:
                # Try to use connection pool first
                pool = self._get_connection_pool(ip)
                
                if pool:
                    connection_info, is_new = await pool.get_connection(ip, port, self.timeout)
                    reader, writer = connection_info[0], connection_info[1]
                    connection_id = connection_info[1]
                    connection_reused = not is_new
                    
                    if is_new:
                        await controller.on_attempt(True)  # New connection
                    else:
                        await controller.on_attempt(True)  # Reused connection
                else:
                    # Fallback to regular connection
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(ip, port), timeout=self.timeout
                    )
                    await controller.on_attempt(True)
                
                latency_ms = (time.monotonic() - t_start) * 1000
                state = PortState.OPEN.value
                self._metrics.increment_port_state("open")
                
                # For pooled connections, we don't close immediately
                # The connection will be returned to pool later
                if not connection_reused:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass

            except asyncio.TimeoutError:
                is_closed = await self._rst_probe(ip, port)
                state = PortState.CLOSED.value if is_closed else PortState.FILTERED.value
                self._metrics.increment_port_state("filtered" if state == PortState.FILTERED.value else "closed")
                await controller.on_attempt(False)

            except ConnectionRefusedError:
                state = PortState.CLOSED.value
                self._metrics.increment_port_state("closed")
                await controller.on_attempt(True)

            except OSError as e:
                if e.errno in (errno.EHOSTUNREACH, 113):
                    state = PortState.UNREACHABLE.value
                    self._metrics.increment_port_state("unreachable")
                elif e.errno in (errno.ECONNREFUSED, 111):
                    state = PortState.CLOSED.value
                    self._metrics.increment_port_state("closed")
                else:
                    state = PortState.ERROR.value
                    self._metrics.increment_port_state("error")
                    await controller.on_attempt(False)
            except Exception:
                state = PortState.ERROR.value
                self._metrics.increment_port_state("error")
                await controller.on_attempt(False)

            result = PortResult(port=port, protocol="tcp", state=state, cves=[], latency_ms=latency_ms)
            
            # Store connection ID for pool management
            if connection_id is not None:
                result._connection_id = connection_id
            
            return result

    async def _process_open_ports(
        self,
        ip: str,
        open_ports_results: List[PortResult],
        banners: List[str],
        valid_ports: List[int],
        latencies: List[float],
        scan_callback: Optional[Callable[[PortResult], Awaitable[None]]] = None,
        run_tls: bool = False
    ):
        for port_res in open_ports_results:
            logger.info(f"Processing port {port_res.port}, state={port_res.state}")
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
                    service_info = None
                    port_res.service = None
                    port_res.banner = None
            except Exception as e:
                logger.error(f"Service detection failed for port {port_res.port}: {e}")
                service_info = None
                port_res.service = None
                port_res.banner = None

            if run_tls and port_res.port in [443, 8443]:
                tls_fp = self._get_tls_fingerprinter()
                if tls_fp:
                    try:
                        tls_info = await tls_fp.get_tls_info(ip, port_res.port)
                        port_res.tls_info = tls_info
                    except Exception:
                        pass

            # Safely get service name
            service_name = service_info.service_name if service_info else "unknown"
            
            try:
                cves = await self.cve_lookup.lookup(service_name, service_info.service_version if service_info else None)
            except Exception as e:
                logger.error(f"CVE lookup failed for {service_name}: {e}")
                cves = []
            port_res.cves = cves

            try:
                risk = self.port_analyzer.analyze(port_res.port, cves)
            except Exception as e:
                logger.error(f"Risk analysis failed for port {port_res.port}: {e}")
                risk = None
            port_res.risk = risk

            valid_ports.append(port_res.port)

            if scan_callback:
                try:
                    await scan_callback(port_res)
                except Exception as e:
                    logger.error(f"Callback failed for port {port_res.port}: {e}")

    async def scan(
        self,
        target: str,
        port_range: str = "common",
        scan_callback: Optional[Callable[[PortResult], Awaitable[None]]] = None,
        resolved_ip: Optional[str] = None,
        scan_mode: str = "connect",
        zombie_ip: Optional[str] = None
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
            try:
                ip = resolve_target(target)
            except Exception:
                try:
                    ip = resolve_target_ipv6(target)
                    is_ipv6 = True
                except Exception:
                    raise ValueError(f"Could not resolve target: {target}")

        started_at = datetime.now(timezone.utc)
        open_ports_results: List[PortResult] = []
        banners: List[str] = []
        valid_ports: List[int] = []
        latencies: List[float] = []
        pool = None  # Initialize pool to avoid UnboundLocalError
        
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
            # Use simple semaphore for rate-limited scans
            rate_pps = self.rate_limiter.get_rate_pps()
            if rate_pps <= 100:
                max_concurrency = 100  # For stealth mode
            elif rate_pps <= 1000:
                max_concurrency = 500  # For normal mode
            else:
                max_concurrency = 1000  # For aggressive mode
            
            # For very large port sets, batch them to avoid memory issues
            batch_size = min(1000, len(ports))
            
            semaphore = asyncio.Semaphore(max_concurrency)
            pool = self._get_connection_pool(ip) if self.enable_connection_pool else None
            
            # Process in batches to prevent memory exhaustion and improve progress reporting
            ports_processed = 0
            for batch_start in range(0, len(ports), batch_size):
                batch = ports[batch_start:batch_start + batch_size]
                tasks = [self._scan_with_retry(ip, port, semaphore) for port in batch]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                ports_processed += len(batch)

                for res in results:
                    if isinstance(res, PortResult):
                        # Collect open ports for processing
                        # Callback will be called AFTER service detection in _process_open_ports
                        if res.state == "open":
                            open_ports_results.append(res)
                            if res.latency_ms is not None:
                                latencies.append(res.latency_ms)

        if open_ports_results:
            await self._process_open_ports(
                ip, open_ports_results, banners, valid_ports, latencies,
                scan_callback, run_tls=(scan_mode == "full")
            )
        
        # Return connections to pool and cleanup
        if pool:
            # Return pooled connections back to pool for reuse
            for res in results:
                if isinstance(res, PortResult) and hasattr(res, '_connection_id'):
                    try:
                        await pool.return_connection(res._connection_id)
                    except Exception:
                        pass

        if scan_mode == "syn":
            for port_res in open_ports_results:
                if port_res.syn_ack_data:
                    self.os_fingerprinter.probe_active(ip, port_res.port)

        # Try active OS fingerprinting first (requires root privileges)
        try:
            os_fingerprint = self.os_fingerprinter.fingerprint_active(ip, valid_ports)
            logger.info(f"Active OS fingerprinting successful for {ip}")
        except PermissionError as e:
            logger.warning(f"Active OS fingerprinting requires root privileges: {e}")
            logger.info(f"Falling back to banner-based OS fingerprinting for {ip}")
            os_fingerprint = self.os_fingerprinter.fingerprint(banners, valid_ports, [p.service for p in open_ports_results])
        except Exception as e:
            logger.warning(f"Active OS fingerprinting failed for {ip}, falling back to banner analysis: {e}")
            os_fingerprint = self.os_fingerprinter.fingerprint(banners, valid_ports, [p.service for p in open_ports_results])

        completed_at = datetime.now(timezone.utc)
        scan_duration = (completed_at - started_at).total_seconds()
        avg_latency = sum(latencies) / len(latencies) if latencies else None

        # Cleanup connection pools
        await self._cleanup_pools()
        
        # ADDED: End metrics tracking
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
            peak_concurrency=max_concurrency if scan_mode == "connect" else 0,
            scan_mode=scan_mode,
            is_ipv6=is_ipv6,
            metrics=stress_metrics,
        )
