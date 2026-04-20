"""
SYN scan implementation using Scapy.
"""
import os
import asyncio
import time
from typing import List, Optional
from dataclasses import dataclass

try:
    from scapy.all import IP, TCP, sr, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from cybersec.core.os_fingerprint import OSFingerprinter

@dataclass
class RetryStats:
    """Statistics for retry operations during SYN scanning."""
    total_retries: int = 0
    timeout_retries: int = 0
    packet_loss_retries: int = 0
    hard_failures: int = 0
    
    def add_retry(self, retry_type: str = "timeout"):
        """Add a retry attempt."""
        self.total_retries += 1
        if retry_type == "timeout":
            self.timeout_retries += 1
        elif retry_type == "packet_loss":
            self.packet_loss_retries += 1
    
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
class PortResult:
    port: int
    protocol: str
    state: str
    service: Optional[object] = None
    os_fingerprint: Optional[object] = None
    cves: List[object] = None
    risk: Optional[object] = None
    banner: Optional[str] = None
    latency_ms: Optional[float] = None

    def __post_init__(self):
        if self.cves is None:
            self.cves = []

class SYNScanner:
    def __init__(self, timeout: float = 3.0, retry_config: Optional[RetryConfig] = None, rate_pps: Optional[float] = None):
        self.timeout = timeout
        self.retry_config = retry_config or RetryConfig()
        self.retry_stats = RetryStats()
        self.rate_pps = rate_pps or 1000.0  # Default to 1000 pps for SYN scans
        self.os_fingerprinter = OSFingerprinter()
        if not SCAPY_AVAILABLE:
            raise ImportError("Scapy not available")
        if os.geteuid() != 0:
            raise PermissionError("SYN scan requires root privileges")

    async def scan_ports(self, ip: str, ports: List[int]) -> List[PortResult]:
        if not SCAPY_AVAILABLE or os.geteuid() != 0:
            # Fallback to connect scan with retry logic
            from cybersec.core.scanner import AsyncPortScanner, RetryConfig
            scanner = AsyncPortScanner(
                timeout=self.timeout, 
                retry_config=self.retry_config,
                rate_pps=self.rate_pps
            )
            report = await scanner.scan(ip, ports, resolved_ip=ip)
            return report.open_ports

        # Build SYN packets
        packets = []
        for port in ports:
            pkt = IP(dst=ip)/TCP(dport=port, flags="S")
            packets.append(pkt)

        # Send with retry logic and rate limiting
        results = []
        batch_size = 100
        
        # Simple rate limiter for SYN scans
        inter_packet_delay = 1.0 / self.rate_pps if self.rate_pps > 0 else 0.001
        
        for i in range(0, len(packets), batch_size):
            batch = packets[i:i+batch_size]
            
            for attempt in range(self.retry_config.max_retries + 1):  # +1 for initial attempt
                start_time = time.time()
                
                try:
                    answered, unanswered = sr(batch, timeout=self.timeout, verbose=0)
                    
                    batch_results = []
                    for sent, received in answered:
                        port = sent[TCP].dport
                        flags = received[TCP].flags
                        latency_ms = (time.time() - start_time) * 1000
                        
                        if flags & 0x12:  # SYN-ACK
                            state = "open"
                            # Feed to OS fingerprinter
                            self.os_fingerprinter.probe_active(received)
                        elif flags & 0x14:  # RST-ACK
                            state = "closed"
                        else:
                            state = "filtered"
                        
                        batch_results.append(PortResult(
                            port=port, protocol="tcp", state=state, 
                            latency_ms=latency_ms
                        ))
                    
                    for sent in unanswered:
                        port = sent[TCP].dport
                        # Check if this is a hard failure (shouldn't retry)
                        if attempt == 0:  # First attempt
                            # For SYN scans, most unanswered are filtered, not hard failures
                            self.retry_stats.add_retry("packet_loss")
                        else:
                            self.retry_stats.add_retry("packet_loss")
                        batch_results.append(PortResult(
                            port=port, protocol="tcp", state="filtered"
                        ))
                    
                    # If we got results or this is the last attempt, break
                    if batch_results or attempt >= self.retry_config.max_retries:
                        results.extend(batch_results)
                        break
                    else:
                        # Retry with exponential backoff
                        delay = self.retry_config.get_delay(attempt)
                        time.sleep(delay)
                        continue
                        
                except Exception as e:
                    if "Permission denied" in str(e) or "Operation not permitted" in str(e):
                        # Hard failure - don't retry
                        self.retry_stats.add_hard_failure()
                        for port in packets[i:i+batch_size]:
                            results.append(PortResult(
                                port=port[TCP].dport, protocol="tcp", state="error"
                            ))
                        break
                    else:
                        # Other exceptions - retry-worthy
                        if attempt < self.retry_config.max_retries:
                            self.retry_stats.add_retry("timeout")
                            delay = self.retry_config.get_delay(attempt)
                            time.sleep(delay)
                            continue
                        else:
                            # Max retries exceeded
                            for port in packets[i:i+batch_size]:
                                results.append(PortResult(
                                    port=port[TCP].dport, protocol="tcp", state="error"
                                ))
                            break
            
            # Rate limiting between batches
            if i + batch_size < len(packets):
                time.sleep(inter_packet_delay * batch_size)

        return results