import asyncio
import socket
from dataclasses import dataclass
from typing import List
import time


@dataclass
class OpenPortDetail:
    port_number: int
    service: str
    status: str


@dataclass
class PortScanResult:
    target: str
    total_scanned: int
    open_ports_count: int
    open_ports: List[OpenPortDetail]
    scan_duration_seconds: float
    error: str | None


# Common port services mapping
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}


def get_service_for_port(port: int) -> str:
    """Get service name for a port number."""
    return COMMON_PORTS.get(port, "Unknown")


async def check_port(target: str, port: int, timeout: float = 2.0) -> OpenPortDetail | None:
    """Check if a single port is open on the target."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target, port),
            timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        
        service = get_service_for_port(port)
        return OpenPortDetail(
            port_number=port,
            service=service,
            status="open"
        )
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return None
    except Exception:
        return None


async def scan_ports(
    target: str,
    ports: List[int] | None = None,
    timeout: float = 2.0,
    max_concurrent: int = 100
) -> PortScanResult:
    """
    Scan multiple ports on a target host concurrently.
    
    Args:
        target: Target hostname or IP address
        ports: List of ports to scan (defaults to common ports)
        timeout: Connection timeout per port in seconds
        max_concurrent: Maximum concurrent connections
    
    Returns:
        PortScanResult with scan details
    """
    start_time = time.time()
    
    # Default to common ports if none specified
    if ports is None:
        ports = list(COMMON_PORTS.keys())
    
    # Resolve target to IP
    try:
        loop = asyncio.get_running_loop()
        ip = (await loop.getaddrinfo(target, None, family=socket.AF_INET))[0][4][0]
    except Exception as e:
        return PortScanResult(
            target=target,
            total_scanned=0,
            open_ports_count=0,
            open_ports=[],
            scan_duration_seconds=0.0,
            error=f"DNS resolution failed: {e}"
        )
    
    # Create semaphore to limit concurrent connections
    semaphore = asyncio.Semaphore(max_concurrent)
    
    async def scan_with_semaphore(port: int) -> OpenPortDetail | None:
        async with semaphore:
            return await check_port(ip, port, timeout)
    
    # Scan all ports concurrently
    tasks = [scan_with_semaphore(port) for port in ports]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    # Filter successful results
    open_ports = []
    for result in results:
        if isinstance(result, OpenPortDetail):
            open_ports.append(result)
    
    scan_duration = time.time() - start_time
    
    return PortScanResult(
        target=target,
        total_scanned=len(ports),
        open_ports_count=len(open_ports),
        open_ports=open_ports,
        scan_duration_seconds=scan_duration,
        error=None
    )


async def scan_port_range(
    target: str,
    start_port: int = 1,
    end_port: int = 1024,
    timeout: float = 2.0,
    max_concurrent: int = 100
) -> PortScanResult:
    """
    Scan a range of ports on a target host.
    
    Args:
        target: Target hostname or IP address
        start_port: Starting port number
        end_port: Ending port number
        timeout: Connection timeout per port in seconds
        max_concurrent: Maximum concurrent connections
    
    Returns:
        PortScanResult with scan details
    """
    ports = list(range(start_port, end_port + 1))
    return await scan_ports(target, ports, timeout, max_concurrent)
