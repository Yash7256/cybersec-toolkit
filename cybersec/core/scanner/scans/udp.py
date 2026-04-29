"""
UDP scan module using Scapy for UDP port scanning.
Requires root privileges. Falls back gracefully if not available.
"""
import os
import asyncio
import struct
import time
from dataclasses import dataclass
from typing import List, Optional, Dict, Any
from concurrent.futures import ThreadPoolExecutor

try:
    from scapy.all import IP, UDP, ICMP, sr1, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

@dataclass
class RetryStats:
    """Statistics for retry operations during UDP scanning."""
    total_retries: int = 0
    timeout_retries: int = 0
    icmp_unreachable_retries: int = 0
    hard_failures: int = 0
    
    def add_retry(self, retry_type: str = "timeout"):
        """Add a retry attempt."""
        self.total_retries += 1
        if retry_type == "timeout":
            self.timeout_retries += 1
        elif retry_type == "icmp_unreachable":
            self.icmp_unreachable_retries += 1
    
    def add_hard_failure(self):
        """Add a hard failure that shouldn't be retried."""
        self.hard_failures += 1

@dataclass
class RetryConfig:
    """Configuration for retry logic."""
    max_retries: int = 3
    base_delay: float = 0.5  # Base delay in seconds
    backoff_multiplier: float = 2.0  # Exponential backoff multiplier
    max_delay: float = 5.0  # Maximum delay between retries
    
    def get_delay(self, attempt: int) -> float:
        """Calculate delay for a specific retry attempt (0-indexed)."""
        delay = self.base_delay * (self.backoff_multiplier ** attempt)
        return min(delay, self.max_delay)

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
    def __init__(self, timeout: float = 3.0, max_rate: int = 100, retry_config: Optional[RetryConfig] = None, rate_pps: Optional[float] = None):
        self.timeout = timeout
        self.max_rate = max_rate
        self.retry_config = retry_config or RetryConfig()
        self.retry_stats = RetryStats()
        self.rate_pps = rate_pps or float(max_rate)  # Use rate_pps or fallback to max_rate
        self._executor = ThreadPoolExecutor(max_workers=10)
        self._has_root = is_root()

    def is_available(self) -> bool:
        return SCAPY_AVAILABLE and self._has_root

    def _sync_scan_port(self, target: str, port: int) -> UDPResult:
        """Scan a single UDP port with retry logic and exponential backoff."""
        if not self.is_available():
            return UDPResult(port=port, state="unavailable")
        
        conf.verb = 0
        payload = UDP_PAYLOADS.get(port, b"\x00" * 10)
        pkt = IP(dst=target)/UDP(dport=port)/payload
        
        for attempt in range(self.retry_config.max_retries + 1):  # +1 for initial attempt
            start_time = time.time()
            
            try:
                resp = sr1(pkt, timeout=self.timeout, verbose=0)
                latency_ms = (time.time() - start_time) * 1000
                
                if resp is None:
                    # No response - could be open|filtered or timeout
                    if attempt < self.retry_config.max_retries:
                        self.retry_stats.add_retry("timeout")
                        delay = self.retry_config.get_delay(attempt)
                        time.sleep(delay)
                        continue
                    else:
                        return UDPResult(port=port, state="open|filtered", 
                                       service=SERVICE_MAP.get(port), latency_ms=latency_ms)
                
                if resp.haslayer(ICMP):
                    icmp_layer = resp[ICMP]
                    if icmp_layer.type == 3:
                        if icmp_layer.code == 3:
                            # Port unreachable - hard failure, don't retry
                            self.retry_stats.add_hard_failure()
                            return UDPResult(port=port, state="closed", service=SERVICE_MAP.get(port))
                        else:
                            # Other ICMP unreachable - retry-worthy
                            if attempt < self.retry_config.max_retries:
                                self.retry_stats.add_retry("icmp_unreachable")
                                delay = self.retry_config.get_delay(attempt)
                                time.sleep(delay)
                                continue
                            else:
                                return UDPResult(port=port, state="filtered", 
                                               service=SERVICE_MAP.get(port))
                    elif icmp_layer.type == 11:
                        # Time exceeded - retry-worthy
                        if attempt < self.retry_config.max_retries:
                            self.retry_stats.add_retry("timeout")
                            delay = self.retry_config.get_delay(attempt)
                            time.sleep(delay)
                            continue
                        else:
                            return UDPResult(port=port, state="filtered", 
                                           service=SERVICE_MAP.get(port))
                
                if resp.haslayer(UDP):
                    # Got UDP response - port is open
                    return UDPResult(port=port, state="open", 
                                   service=SERVICE_MAP.get(port), latency_ms=latency_ms)
                
                # Got some other response - treat as filtered
                if attempt < self.retry_config.max_retries:
                    self.retry_stats.add_retry("timeout")
                    delay = self.retry_config.get_delay(attempt)
                    time.sleep(delay)
                    continue
                else:
                    return UDPResult(port=port, state="open|filtered", 
                                   service=SERVICE_MAP.get(port), latency_ms=latency_ms)
                    
            except Exception as e:
                # Handle various exceptions
                if "Permission denied" in str(e) or "Operation not permitted" in str(e):
                    # Hard failure - don't retry
                    self.retry_stats.add_hard_failure()
                    return UDPResult(port=port, state="error")
                else:
                    # Other exceptions - retry-worthy
                    if attempt < self.retry_config.max_retries:
                        self.retry_stats.add_retry("timeout")
                        delay = self.retry_config.get_delay(attempt)
                        time.sleep(delay)
                        continue
                    else:
                        return UDPResult(port=port, state="error")
        
        # Should not reach here, but just in case
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
        
        # Calculate rate limiting delay
        inter_packet_delay = 1.0 / self.rate_pps if self.rate_pps > 0 else 0.001
        
        results = []
        total = len(ports)
        
        for i, port in enumerate(ports):
            # Apply rate limiting
            if i > 0:
                time.sleep(inter_packet_delay)
            
            # Submit scan task to thread pool
            result = await asyncio.get_event_loop().run_in_executor(
                self._executor, self._sync_scan_port, target, port
            )
            
            results.append(result)
            
            if progress_callback:
                progress_callback(i + 1, total)
        
        return results
