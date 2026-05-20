import asyncio
from dataclasses import dataclass, field
from typing import List, Optional
import time
from cybersec.core.tools.port_scanner import scan_ports, scan_port_range, COMMON_PORTS


@dataclass
class OpenPort:
    port: int
    state: str
    service: str


@dataclass
class ScanMetrics:
    total_ports_scanned: int
    open_ports_found: int
    scan_duration_seconds: float
    ports_per_second: float


@dataclass
class ScanResult:
    target: str
    open_ports: List[OpenPort] = field(default_factory=list)
    metrics: ScanMetrics = None


class AsyncPortScanner:
    """Async port scanner with rate limiting and concurrency control."""
    
    def __init__(
        self,
        timeout: float = 3.0,
        rate_preset: str = "normal",
        rate_pps: Optional[int] = None,
        enable_connection_pool: bool = False,
    ):
        self.timeout = timeout
        self.rate_preset = rate_preset
        self.rate_pps = rate_pps
        self.enable_connection_pool = enable_connection_pool
        
        # Calculate max concurrent based on rate settings
        if rate_pps:
            self.max_concurrent = min(rate_pps, 2000)
        elif rate_preset == "aggressive":
            self.max_concurrent = 1000
        elif rate_preset == "slow":
            self.max_concurrent = 50
        else:  # normal
            self.max_concurrent = 250
    
    async def scan(self, target: str, port_range: str = "common") -> ScanResult:
        """
        Scan a target for open ports.
        
        Args:
            target: Target hostname or IP address
            port_range: Port range specification ("common", "1-1000", etc.)
        
        Returns:
            ScanResult with open ports and metrics
        """
        start_time = time.time()
        
        # Determine ports to scan
        if port_range == "common":
            ports = list(COMMON_PORTS.keys())
        elif "-" in port_range:
            start, end = map(int, port_range.split("-"))
            ports = list(range(start, end + 1))
        elif "," in port_range:
            ports = [int(p.strip()) for p in port_range.split(",") if p.strip().isdigit()]
        else:
            ports = list(COMMON_PORTS.keys())
        
        # Perform scan
        result = await scan_ports(
            target=target,
            ports=ports,
            timeout=self.timeout,
            max_concurrent=self.max_concurrent
        )
        
        # Convert to expected format
        open_ports = [
            OpenPort(
                port=p.port_number,
                state=p.status,
                service=p.service
            )
            for p in result.open_ports
        ]
        
        scan_duration = time.time() - start_time
        metrics = ScanMetrics(
            total_ports_scanned=result.total_scanned,
            open_ports_found=result.open_ports_count,
            scan_duration_seconds=scan_duration,
            ports_per_second=result.total_scanned / scan_duration if scan_duration > 0 else 0
        )
        
        return ScanResult(
            target=target,
            open_ports=open_ports,
            metrics=metrics
        )
