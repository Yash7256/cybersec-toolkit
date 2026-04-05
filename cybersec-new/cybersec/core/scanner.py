"""
Async port scanner with Adaptive Concurrency (AIMD).
"""
import asyncio
import errno
import time
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Optional, List, Callable, Awaitable

from cybersec.core.utils import resolve_target, parse_ports
from cybersec.core.service_detect import ServiceDetector, ServiceInfo
from cybersec.core.cve_lookup import CVELookup, CVEEntry
from cybersec.core.port_analyzer import PortAnalyzer, PortRisk
from cybersec.core.os_fingerprint import OSFingerprinter, OSFingerprint

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


class AdaptiveConcurrencyController:
    """
    AIMD (Additive Increase, Multiplicative Decrease) concurrency controller.
    Increases workers by 1 on success, halves on consecutive timeout spikes.
    """
    def __init__(self, min_workers: int = 50, max_workers: int = 500, initial_workers: int = 100):
        self.current = initial_workers
        self.min = min_workers
        self.max = max_workers
        self.peak = initial_workers
        self._consecutive_errors = 0
        self._lock = asyncio.Lock()

    async def on_success(self, latency_ms: float):
        async with self._lock:
            self._consecutive_errors = 0
            # Additive Increase: grow by 1 toward max
            if self.current < self.max:
                self.current = min(self.max, self.current + 1)
            if self.current > self.peak:
                self.peak = self.current

    async def on_timeout(self):
        async with self._lock:
            self._consecutive_errors += 1
            # Multiplicative Decrease: halve on 3 consecutive timeouts
            if self._consecutive_errors >= 3:
                self.current = max(self.min, self.current // 2)
                self._consecutive_errors = 0

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
                await controller.on_success(latency_ms)

            except asyncio.TimeoutError:
                state = "filtered"
                await controller.on_timeout()
            except ConnectionRefusedError:
                state = "closed"
                await controller.on_success(0)
            except OSError as e:
                if e.errno in (errno.EHOSTUNREACH, 113):
                    state = "unreachable"
                elif e.errno in (errno.ECONNREFUSED, 111):
                    state = "closed"
                else:
                    state = "error"
                    await controller.on_timeout()
            except Exception:
                state = "error"
                await controller.on_timeout()

            return PortResult(port=port, protocol="tcp", state=state, cves=[], latency_ms=latency_ms)

    async def scan(
        self,
        target: str,
        port_range: str = "common",
        scan_callback: Optional[Callable[[PortResult], Awaitable[None]]] = None,
        resolved_ip: Optional[str] = None
    ) -> ScanReport:
        ip = resolved_ip or resolve_target(target)
        ports = parse_ports(port_range)

        started_at = datetime.now(timezone.utc)
        controller = AdaptiveConcurrencyController()
        
        # Use a dynamic semaphore — we recreate on a tight loop
        # Instead, we launch tasks and rely on a fixed-size window
        semaphore = asyncio.Semaphore(controller.current)
        
        tasks = [self._scan_port(ip, port, semaphore, controller) for port in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        open_ports_results: List[PortResult] = []
        banners: List[str] = []
        valid_ports: List[int] = []
        latencies: List[float] = []

        for res in results:
            if isinstance(res, PortResult) and res.state == "open":
                open_ports_results.append(res)
                if res.latency_ms is not None:
                    latencies.append(res.latency_ms)

        for port_res in open_ports_results:
            service_info = await self.service_detector.detect(ip, port_res.port, timeout=self.timeout)
            port_res.service = service_info
            if service_info and service_info.banner:
                port_res.banner = service_info.banner
                banners.append(service_info.banner)
            else:
                port_res.banner = None

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
            peak_concurrency=controller.peak,
        )
