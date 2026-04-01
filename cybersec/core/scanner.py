import asyncio
import logging
import socket
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

from cybersec.core.cve_lookup import CVELookup, CVEEntry
from cybersec.core.os_fingerprint import OSFingerprinter
from cybersec.core.port_analyzer import PortAnalyzer
from cybersec.core.service_detect import ServiceDetector
from cybersec.core.utils import parse_ports, resolve_target

logger = logging.getLogger(__name__)


@dataclass
class PortResult:
    port: int
    protocol: str
    state: str
    service: str
    version: str | None
    banner: str
    os_hint: str | None
    cves: list[CVEEntry] = field(default_factory=list)
    risk_score: float = 0.0


@dataclass
class ScanReport:
    target: str
    ip: str
    ports_scanned: int
    open_ports: list[PortResult]
    scan_duration: float
    timestamp: datetime
    scan_type: str = "tcp"


class AsyncPortScanner:
    def __init__(self) -> None:
        self.service_detector = ServiceDetector()
        self.cve_lookup = CVELookup()
        self.port_analyzer = PortAnalyzer()
        self.os_fingerprinter = OSFingerprinter()

    async def scan(
        self,
        target: str,
        ports: str = "common",
        protocol: str = "tcp",
        timeout: float = 1.0,
        concurrency: int = 500,
        on_progress: Callable | None = None,
    ) -> ScanReport:
        start_time = time.monotonic()

        try:
            resolved_ip = resolve_target(target)
        except ValueError as e:
            logger.error(f"Failed to resolve target '{target}': {e}")
            raise

        port_list = parse_ports(ports)
        ports_scanned = len(port_list)

        logger.info(f"Starting scan on {target} ({resolved_ip}), ports: {ports}, protocol: {protocol}")

        open_ports: list[PortResult] = []
        semaphore = asyncio.Semaphore(concurrency)

        async def scan_port(port: int, proto: str) -> PortResult | None:
            async with semaphore:
                result = await self._scan_single_port(resolved_ip, port, proto, timeout)
                if result and result.state == "open":
                    if on_progress:
                        on_progress(port, result.state, result.service)
                    return result
                elif on_progress:
                    on_progress(port, result.state if result else "unknown", "")
                return None

        tasks: list[asyncio.Task] = []

        if protocol in ("tcp", "both"):
            for port in port_list:
                task = asyncio.create_task(scan_port(port, "tcp"))
                tasks.append(task)

        if protocol in ("udp", "both") and "both" not in protocol:
            for port in port_list:
                task = asyncio.create_task(scan_port(port, "udp"))
                tasks.append(task)

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, PortResult) and result is not None:
                open_ports.append(result)

        scan_duration = time.monotonic() - start_time

        open_ports.sort(key=lambda x: x.port)

        logger.info(
            f"Scan complete: {len(open_ports)} open ports found in {scan_duration:.2f}s"
        )

        return ScanReport(
            target=target,
            ip=resolved_ip,
            ports_scanned=ports_scanned,
            open_ports=open_ports,
            scan_duration=scan_duration,
            timestamp=datetime.now(timezone.utc),
            scan_type=protocol,
        )

    async def _scan_single_port(
        self, host: str, port: int, protocol: str = "tcp", timeout: float = 1.0
    ) -> PortResult:
        if protocol.lower() == "tcp":
            return await self._scan_tcp(host, port, timeout)
        else:
            return await self._scan_udp(host, port, timeout)

    async def _scan_tcp(self, host: str, port: int, timeout: float) -> PortResult:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout,
            )

            service_info = await self.service_detector.detect(host, port, "tcp", timeout)

            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass

            cves = self.cve_lookup.lookup(service_info.name, service_info.version)
            os_hint = self.os_fingerprinter.fingerprint(service_info.banner, port)
            risk_score = self.port_analyzer.calculate_risk_score(
                port, service_info.name, cves
            )

            return PortResult(
                port=port,
                protocol="tcp",
                state="open",
                service=service_info.name,
                version=service_info.version,
                banner=service_info.banner,
                os_hint=os_hint,
                cves=cves,
                risk_score=risk_score,
            )

        except asyncio.TimeoutError:
            return PortResult(
                port=port,
                protocol="tcp",
                state="filtered",
                service=self.port_analyzer.get_service_name(port),
                version=None,
                banner="",
                os_hint=None,
                cves=[],
                risk_score=0.0,
            )
        except ConnectionRefusedError:
            return PortResult(
                port=port,
                protocol="tcp",
                state="closed",
                service=self.port_analyzer.get_service_name(port),
                version=None,
                banner="",
                os_hint=None,
                cves=[],
                risk_score=0.0,
            )
        except OSError as e:
            if e.errno == 111:
                return PortResult(
                    port=port,
                    protocol="tcp",
                    state="closed",
                    service=self.port_analyzer.get_service_name(port),
                    version=None,
                    banner="",
                    os_hint=None,
                    cves=[],
                    risk_score=0.0,
                )
            elif e.errno == 113:
                return PortResult(
                    port=port,
                    protocol="tcp",
                    state="unreachable",
                    service=self.port_analyzer.get_service_name(port),
                    version=None,
                    banner="",
                    os_hint=None,
                    cves=[],
                    risk_score=0.0,
                )
            else:
                logger.warning(
                    f"Port {port}: {type(e).__name__}: {e}"
                )
                return PortResult(
                    port=port,
                    protocol="tcp",
                    state="error",
                    service=self.port_analyzer.get_service_name(port),
                    version=None,
                    banner="",
                    os_hint=None,
                    cves=[],
                    risk_score=0.0,
                )
        except Exception as e:
            logger.warning(f"Port {port}: {type(e).__name__}: {e}")
            return PortResult(
                port=port,
                protocol="tcp",
                state="error",
                service=self.port_analyzer.get_service_name(port),
                version=None,
                banner="",
                os_hint=None,
                cves=[],
                risk_score=0.0,
            )

    async def _scan_udp(self, host: str, port: int, timeout: float) -> PortResult:
        loop = asyncio.get_event_loop()

        def sync_udp_scan():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(timeout)
                sock.sendto(b"", (host, port))
                data, _ = sock.recvfrom(1024)
                sock.close()
                return data
            except socket.timeout:
                sock.close()
                return None
            except ConnectionRefusedError:
                sock.close()
                return None
            except OSError as e:
                sock.close()
                if e.errno in (111, 113):
                    return None
                raise

        try:
            response = await asyncio.wait_for(
                loop.run_in_executor(None, sync_udp_scan),
                timeout=timeout + 0.5,
            )

            if response is None:
                return PortResult(
                    port=port,
                    protocol="udp",
                    state="filtered",
                    service=self.port_analyzer.get_service_name(port),
                    version=None,
                    banner="",
                    os_hint=None,
                    cves=[],
                    risk_score=0.0,
                )

            service_info = await self.service_detector.detect(host, port, "udp", timeout)
            decoded = response.decode("utf-8", errors="replace") if response else ""

            cves = self.cve_lookup.lookup(service_info.name, service_info.version)
            os_hint = self.os_fingerprinter.fingerprint(decoded, port)
            risk_score = self.port_analyzer.calculate_risk_score(
                port, service_info.name, cves
            )

            return PortResult(
                port=port,
                protocol="udp",
                state="open",
                service=service_info.name,
                version=service_info.version,
                banner=decoded[:500],
                os_hint=os_hint,
                cves=cves,
                risk_score=risk_score,
            )

        except asyncio.TimeoutError:
            return PortResult(
                port=port,
                protocol="udp",
                state="filtered",
                service=self.port_analyzer.get_service_name(port),
                version=None,
                banner="",
                os_hint=None,
                cves=[],
                risk_score=0.0,
            )
        except ConnectionRefusedError:
            return PortResult(
                port=port,
                protocol="udp",
                state="closed",
                service=self.port_analyzer.get_service_name(port),
                version=None,
                banner="",
                os_hint=None,
                cves=[],
                risk_score=0.0,
            )
        except OSError as e:
            if e.errno == 111:
                return PortResult(
                    port=port,
                    protocol="udp",
                    state="closed",
                    service=self.port_analyzer.get_service_name(port),
                    version=None,
                    banner="",
                    os_hint=None,
                    cves=[],
                    risk_score=0.0,
                )
            elif e.errno == 113:
                return PortResult(
                    port=port,
                    protocol="udp",
                    state="unreachable",
                    service=self.port_analyzer.get_service_name(port),
                    version=None,
                    banner="",
                    os_hint=None,
                    cves=[],
                    risk_score=0.0,
                )
            else:
                logger.warning(f"Port {port}: {type(e).__name__}: {e}")
                return PortResult(
                    port=port,
                    protocol="udp",
                    state="error",
                    service=self.port_analyzer.get_service_name(port),
                    version=None,
                    banner="",
                    os_hint=None,
                    cves=[],
                    risk_score=0.0,
                )
        except Exception as e:
            logger.warning(f"Port {port}: {type(e).__name__}: {e}")
            return PortResult(
                port=port,
                protocol="udp",
                state="error",
                service=self.port_analyzer.get_service_name(port),
                version=None,
                banner="",
                os_hint=None,
                cves=[],
                risk_score=0.0,
            )
