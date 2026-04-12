"""
SYN scan implementation using Scapy.
"""
import os
import asyncio
from typing import List, Optional
from dataclasses import dataclass

try:
    from scapy.all import IP, TCP, sr, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from cybersec.core.os_fingerprint import OSFingerprinter

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
    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout
        self.os_fingerprinter = OSFingerprinter()
        if not SCAPY_AVAILABLE:
            raise ImportError("Scapy not available")
        if os.geteuid() != 0:
            raise PermissionError("SYN scan requires root privileges")

    async def scan_ports(self, ip: str, ports: List[int]) -> List[PortResult]:
        if not SCAPY_AVAILABLE or os.geteuid() != 0:
            # Fallback to connect scan
            from cybersec.core.scanner import AsyncPortScanner
            scanner = AsyncPortScanner()
            report = await scanner.scan(ip, ports, resolved_ip=ip)
            return report.open_ports

        # Build SYN packets
        packets = []
        for port in ports:
            pkt = IP(dst=ip)/TCP(dport=port, flags="S")
            packets.append(pkt)

        # Send in batches
        results = []
        batch_size = 100
        for i in range(0, len(packets), batch_size):
            batch = packets[i:i+batch_size]
            answered, unanswered = sr(batch, timeout=self.timeout, verbose=0)
            
            for sent, received in answered:
                port = sent[TCP].dport
                flags = received[TCP].flags
                if flags & 0x12:  # SYN-ACK
                    state = "open"
                    # Feed to OS fingerprinter
                    self.os_fingerprinter.probe_active(received)
                elif flags & 0x14:  # RST-ACK
                    state = "closed"
                else:
                    state = "filtered"
                results.append(PortResult(port=port, protocol="tcp", state=state))
            
            for sent in unanswered:
                port = sent[TCP].dport
                results.append(PortResult(port=port, protocol="tcp", state="filtered"))

        return results