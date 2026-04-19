"""
Async port scanner with Adaptive Concurrency (AIMD).
Supports multiple scan modes: connect, syn, udp, stealth_*, zombie, full
"""
import asyncio
import errno
import socket
import time
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Optional, List, Callable, Awaitable, Dict, Any

from cybersec.core.utils import resolve_target, parse_ports, resolve_target_ipv6
from cybersec.core.service_detect import ServiceDetector, ServiceInfo
from cybersec.core.cve_lookup import CVELookup, CVEEntry
from cybersec.core.port_analyzer import PortAnalyzer, PortRisk
from cybersec.core.os_fingerprint import OSFingerprinter, OSFingerprint

try:
    from scapy.all import IP, TCP, ICMP, sr1, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

@dataclass
class PortResult:
    port: int
    protocol: str
    state: str
    service: Optional[ServiceInfo] = None
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
    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout
        self.service_detector = ServiceDetector()
        self.cve_lookup = CVELookup()
        self.port_analyzer = PortAnalyzer()
        self.os_fingerprinter = OSFingerprinter()
        self._syn_scanner = None
        self._udp_scanner = None
        self._stealth_scanner = None
        self._zombie_scanner = None
        self._tls_fingerprinter = None

    def _get_syn_scanner(self):
        if self._syn_scanner is None:
            try:
                from cybersec.core.syn_scan import SYNScanner
                self._syn_scanner = SYNScanner(timeout=self.timeout)
            except (ImportError, PermissionError):
                self._syn_scanner = None
        return self._syn_scanner

    def _get_udp_scanner(self):
        if self._udp_scanner is None:
            try:
                from cybersec.core.udp_scan import UDPScanner
                self._udp_scanner = UDPScanner(timeout=self.timeout)
            except (ImportError, PermissionError):
                self._udp_scanner = None
        return self._udp_scanner

    def _get_stealth_scanner(self):
        if self._stealth_scanner is None:
            try:
                from cybersec.core.stealth import StealthScanner
                self._stealth_scanner = StealthScanner(timeout=self.timeout)
            except (ImportError, PermissionError):
                self._stealth_scanner = None
        return self._stealth_scanner

    def _get_zombie_scanner(self, zombie_ip: str):
        try:
            from cybersec.core.zombie_scan import ZombieScanner
            return ZombieScanner(zombie_ip=zombie_ip, timeout=self.timeout)
        except (ImportError, PermissionError):
            return None

    def _get_tls_fingerprinter(self):
        if self._tls_fingerprinter is None:
            try:
                from cybersec.core.tls_fingerprint import TLSFingerprinter
                self._tls_fingerprinter = TLSFingerprinter(timeout=self.timeout)
            except ImportError:
                self._tls_fingerprinter = None
        return self._tls_fingerprinter

    def _is_ipv6(self, target: str) -> bool:
        try:
            socket.inet_pton(socket.AF_INET6, target)
            return True
        except socket.error:
            return False

    async def _rst_probe(self, ip: str, port: int) -> bool:
        """
        Enhanced RST probe using Scapy for reliable filtered vs closed detection.
        
        Logic:
        1. Send SYN packet and analyze response
        2. SYN-ACK = port is open (should not happen in timeout scenario)
        3. RST = port is closed (host actively refused)
        4. No response/ICMP unreachable = filtered (firewall/drop)
        5. Retry up to 2 times with exponential backoff
        """
        if not SCAPY_AVAILABLE:
            # Fallback to original method if Scapy unavailable
            return await self._rst_probe_fallback(ip, port)
        
        # Try up to 2 times with increasing timeouts
        for attempt in range(2):
            timeout = 1.0 + (attempt * 0.5)  # 1.0s, 1.5s
            
            try:
                # Disable Scapy verbosity for this probe
                conf.verb = 0
                
                # Craft SYN packet
                syn_pkt = IP(dst=ip)/TCP(dport=port, flags="S", seq=1000 + attempt)
                
                # Send packet and wait for response
                response = sr1(syn_pkt, timeout=timeout, verbose=0)
                
                if response is None:
                    # No response = filtered (firewall dropped packet)
                    continue  # Try next attempt
                    
                # Check if we got any response
                if hasattr(response, 'haslayer'):
                    # Check for TCP layer in response
                    if response.haslayer(TCP):
                        tcp_layer = response[TCP]
                        tcp_flags = tcp_layer.flags
                        
                        # SYN-ACK (0x12) = port is open (shouldn't happen but handle)
                        if tcp_flags & 0x12:  # SYN+ACK
                            # This means port is open, but we're in timeout context
                            # This is unexpected but we handle it gracefully
                            return False
                            
                        # RST (0x04) or RST-ACK (0x14) = port is closed  
                        elif tcp_flags & 0x04:  # RST flag set
                            return True  # Port is closed
                            
                    # Check for ICMP layer (destination unreachable)
                    if response.haslayer(ICMP):
                        icmp_layer = response[ICMP]
                        # ICMP Type 3 = Destination Unreachable = filtered
                        if icmp_layer.type == 3:
                            return False  # Port is filtered
                            
                # If we get here, we got an unclassified response
                # Default to filtered for safety
                return False
                
            except Exception as e:
                # On any error, try next attempt
                if attempt == 1:  # Only log on first attempt
                    pass  # Silently handle for production
                continue
                
        # If all attempts failed with no response, assume filtered
        return False
    
    async def _rst_probe_fallback(self, ip: str, port: int) -> bool:
        """
        Fallback method using asyncio when Scapy is unavailable.
        Less accurate but maintains functionality.
        """
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=1.0
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return True  # Got connection = closed
        except ConnectionRefusedError:
            return True  # Explicit refusal = closed
        except (asyncio.TimeoutError, OSError):
            return False  # Timeout = filtered
        except Exception:
            return False  # Any other error = filtered

    async def _scan_port(
        self,
        ip: str,
        port: int,
        semaphore: asyncio.Semaphore,
        controller: AdaptiveConcurrencyController
    ) -> PortResult:
        async with semaphore:
            t_start = time.monotonic()
            state = "closed"
            latency_ms = None
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port), timeout=self.timeout
                )
                latency_ms = (time.monotonic() - t_start) * 1000
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                state = "open"
                await controller.on_attempt(True)

            except asyncio.TimeoutError:
                is_closed = await self._rst_probe(ip, port)
                state = "closed" if is_closed else "filtered"
                await controller.on_attempt(False)

            except ConnectionRefusedError:
                state = "closed"
                await controller.on_attempt(True)

            except OSError as e:
                if e.errno in (errno.EHOSTUNREACH, 113):
                    state = "unreachable"
                elif e.errno in (errno.ECONNREFUSED, 111):
                    state = "closed"
                else:
                    state = "error"
                    await controller.on_attempt(False)
            except Exception:
                state = "error"
                await controller.on_attempt(False)

            return PortResult(port=port, protocol="tcp", state=state, cves=[], latency_ms=latency_ms)

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
            service_info = await self.service_detector.detect(ip, port_res.port, timeout=self.timeout)
            port_res.service = service_info
            if service_info and service_info.banner:
                port_res.banner = service_info.banner
                banners.append(service_info.banner)
            else:
                port_res.banner = None

            if run_tls and port_res.port in [443, 8443]:
                tls_fp = self._get_tls_fingerprinter()
                if tls_fp:
                    try:
                        tls_info = await tls_fp.get_tls_info(ip, port_res.port)
                        port_res.tls_info = tls_info
                    except Exception:
                        pass

            cves = self.cve_lookup.lookup(service_info.name, service_info.version)
            port_res.cves = cves

            risk = self.port_analyzer.analyze(port_res.port, cves)
            port_res.risk = risk

            valid_ports.append(port_res.port)

            if scan_callback:
                try:
                    await scan_callback(port_res)
                except Exception:
                    pass

    async def scan(
        self,
        target: str,
        port_range: str = "common",
        scan_callback: Optional[Callable[[PortResult], Awaitable[None]]] = None,
        resolved_ip: Optional[str] = None,
        scan_mode: str = "connect",
        zombie_ip: Optional[str] = None
    ) -> ScanReport:
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

        if scan_mode == "connect" or scan_mode == "full":
            controller = AdaptiveConcurrencyController()
            semaphore = controller.get_semaphore()
            
            tasks = [self._scan_port(ip, port, semaphore, controller) for port in ports]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for res in results:
                if isinstance(res, PortResult) and res.state == "open":
                    open_ports_results.append(res)
                    if res.latency_ms is not None:
                        latencies.append(res.latency_ms)

        if open_ports_results:
            await self._process_open_ports(
                ip, open_ports_results, banners, valid_ports, latencies,
                scan_callback, run_tls=(scan_mode == "full")
            )

        if scan_mode == "syn":
            for port_res in open_ports_results:
                if port_res.syn_ack_data:
                    self.os_fingerprinter.probe_active(ip, port_res.port)

        os_fingerprint = self.os_fingerprinter.fingerprint(banners, valid_ports, [p.service for p in open_ports_results])

        completed_at = datetime.now(timezone.utc)
        scan_duration = (completed_at - started_at).total_seconds()
        avg_latency = sum(latencies) / len(latencies) if latencies else None

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
            peak_concurrency=controller.peak if scan_mode == "connect" else 0,
            scan_mode=scan_mode,
            is_ipv6=is_ipv6,
        )
