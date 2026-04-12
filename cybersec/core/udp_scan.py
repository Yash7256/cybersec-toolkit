"""
UDP scan module using Scapy for UDP port scanning.
Requires root privileges. Falls back gracefully if not available.
"""
import os
import asyncio
import struct
from dataclasses import dataclass
from typing import List, Optional, Dict, Any
from concurrent.futures import ThreadPoolExecutor

try:
    from scapy.all import IP, UDP, ICMP, sr1, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

@dataclass
class UDPResult:
    port: int
    state: str
    protocol: str = "udp"
    service: Optional[str] = None
    latency_ms: Optional[float] = None

UDP_PAYLOADS = {
    53: b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01",
    123: b"\x23\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    161: b"\x30\x26\x02\x01\x00\x04\x06public\xa0\x19\x02\x01\x00\x02\x01\x00\x02\x01\x00\x30\x0e\x30\x0c\x06\x08\x2b\x06\x01\x02\x01\x01\x00\x05\x00",
    137: b"\x80\x98\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x20\x43\x4b\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00\x00\x21\x00\x01",
    500: b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
}

SERVICE_MAP = {
    53: "dns",
    123: "ntp",
    161: "snmp",
    137: "netbios-ns",
    500: "isakmp",
    69: "tftp",
    514: "syslog",
    520: "rip",
    1900: "ssdp",
    5353: "mdns",
}

def is_root() -> bool:
    return os.geteuid() == 0 if hasattr(os, 'geteuid') else False

class UDPScanner:
    def __init__(self, timeout: float = 3.0, max_rate: int = 100):
        self.timeout = timeout
        self.max_rate = max_rate
        self._executor = ThreadPoolExecutor(max_workers=10)
        self._has_root = is_root()

    def is_available(self) -> bool:
        return SCAPY_AVAILABLE and self._has_root

    def _sync_scan_port(self, target: str, port: int) -> UDPResult:
        if not self.is_available():
            return UDPResult(port=port, state="unavailable")
        
        conf.verb = 0
        payload = UDP_PAYLOADS.get(port, b"\x00" * 10)
        pkt = IP(dst=target)/UDP(dport=port)/payload
        
        try:
            resp = sr1(pkt, timeout=self.timeout, verbose=0)
            
            if resp is None:
                return UDPResult(port=port, state="open|filtered", service=SERVICE_MAP.get(port))
            
            if resp.haslayer(ICMP):
                icmp_layer = resp[ICMP]
                if icmp_layer.type == 3:
                    if icmp_layer.code == 3:
                        return UDPResult(port=port, state="closed", service=SERVICE_MAP.get(port))
                    else:
                        return UDPResult(port=port, state="filtered", service=SERVICE_MAP.get(port))
                elif icmp_layer.type == 11:
                    return UDPResult(port=port, state="filtered", service=SERVICE_MAP.get(port))
            
            if resp.haslayer(UDP):
                return UDPResult(port=port, state="open", service=SERVICE_MAP.get(port))
            
            return UDPResult(port=port, state="open|filtered", service=SERVICE_MAP.get(port))
                
        except Exception:
            return UDPResult(port=port, state="error")

    async def scan_port(self, target: str, port: int, retry: bool = True) -> UDPResult:
        result = await self._scan_port_async(target, port)
        if result.state == "open|filtered" and retry:
            result_retry = await self._scan_port_async(target, port)
            if result_retry.state == "closed":
                return result_retry
        return result

    async def _scan_port_async(self, target: str, port: int) -> UDPResult:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(self._executor, self._sync_scan_port, target, port)

    async def scan(
        self,
        target: str,
        ports: List[int],
        progress_callback: Optional[callable] = None
    ) -> List[UDPResult]:
        if not self.is_available():
            return [UDPResult(port=p, state="requires_root") for p in ports]
        
        results = []
        total = len(ports)
        rate_limiter = asyncio.Semaphore(self.max_rate)
        
        async def scan_with_rate_limit(port: int) -> UDPResult:
            async with rate_limiter:
                result = await self.scan_port(target, port)
                if progress_callback:
                    progress_callback(len(results) + 1, total)
                return result
        
        tasks = [scan_with_rate_limit(port) for port in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        return [r if isinstance(r, UDPResult) else UDPResult(port=port, state="error") 
                for r, port in zip(results, ports)]
