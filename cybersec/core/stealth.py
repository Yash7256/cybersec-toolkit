"""
Stealth and evasion scan modes: FIN/NULL/XMAS, Fragmented, Decoy.
Requires root privileges.
"""
import os
import asyncio
import random
from dataclasses import dataclass
from typing import List, Optional, Dict, Any
from concurrent.futures import ThreadPoolExecutor

try:
    from scapy.all import IP, TCP, fragment, conf, sr1, RandIP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

@dataclass
class StealthResult:
    port: int
    state: str
    protocol: str = "tcp"
    scan_type: str = "stealth"
    ttl: Optional[int] = None

def is_root() -> bool:
    return os.geteuid() == 0 if hasattr(os, 'geteuid') else False

class StealthScanner:
    SCAN_MODES = {
        "fin": 0x01,
        "null": 0x00,
        "xmas": 0x29,
        "ack": 0x10,
    }
    
    def __init__(self, timeout: float = 3.0, decoy_count: int = 3):
        self.timeout = timeout
        self.decoy_count = decoy_count
        self._executor = ThreadPoolExecutor(max_workers=10)
        self._has_root = is_root()

    def is_available(self) -> bool:
        return SCAPY_AVAILABLE and self._has_root

    def _build_base_packet(self, target: str, port: int, flags: int = 0) -> IP:
        return IP(dst=target)/TCP(dport=port, flags=flags, seq=1000)

    def _sync_fin_scan(self, target: str, port: int) -> StealthResult:
        if not self.is_available():
            return StealthResult(port=port, state="requires_root", scan_type="fin")
        
        conf.verb = 0
        pkt = self._build_base_packet(target, port, flags="F")
        
        try:
            resp = sr1(pkt, timeout=self.timeout, verbose=0)
            
            if resp is None:
                return StealthResult(port=port, state="open|filtered", scan_type="fin")
            
            if resp.haslayer(TCP):
                flags = resp[TCP].flags
                if flags & 0x04:
                    return StealthResult(port=port, state="closed", scan_type="fin")
                else:
                    return StealthResult(port=port, state="filtered", scan_type="fin")
            
            return StealthResult(port=port, state="filtered", scan_type="fin")
            
        except Exception:
            return StealthResult(port=port, state="error", scan_type="fin")

    def _sync_null_scan(self, target: str, port: int) -> StealthResult:
        if not self.is_available():
            return StealthResult(port=port, state="requires_root", scan_type="null")
        
        conf.verb = 0
        pkt = self._build_base_packet(target, port, flags="")
        
        try:
            resp = sr1(pkt, timeout=self.timeout, verbose=0)
            
            if resp is None:
                return StealthResult(port=port, state="open|filtered", scan_type="null")
            
            if resp.haslayer(TCP):
                flags = resp[TCP].flags
                if flags & 0x04:
                    return StealthResult(port=port, state="closed", scan_type="null")
                else:
                    return StealthResult(port=port, state="filtered", scan_type="null")
            
            return StealthResult(port=port, state="filtered", scan_type="null")
            
        except Exception:
            return StealthResult(port=port, state="error", scan_type="null")

    def _sync_xmas_scan(self, target: str, port: int) -> StealthResult:
        if not self.is_available():
            return StealthResult(port=port, state="requires_root", scan_type="xmas")
        
        conf.verb = 0
        pkt = self._build_base_packet(target, port, flags="FPU")
        
        try:
            resp = sr1(pkt, timeout=self.timeout, verbose=0)
            
            if resp is None:
                return StealthResult(port=port, state="open|filtered", scan_type="xmas")
            
            if resp.haslayer(TCP):
                flags = resp[TCP].flags
                if flags & 0x04:
                    return StealthResult(port=port, state="closed", scan_type="xmas")
                else:
                    return StealthResult(port=port, state="filtered", scan_type="xmas")
            
            return StealthResult(port=port, state="filtered", scan_type="xmas")
            
        except Exception:
            return StealthResult(port=port, state="error", scan_type="xmas")

    def _sync_ack_scan(self, target: str, port: int) -> StealthResult:
        """ACK scan: sends ACK with seq=0. RST response = unfiltered; no response = filtered/filtered.

        ACK scan maps firewall rules rather than finding open ports.
        - RST received → port is UNFILTERED (no firewall rule blocking)
        - No response → port is FILTERED (firewall is blocking)
        - Used to discover firewall rule sets, not port state.
        """
        if not self.is_available():
            return StealthResult(port=port, state="requires_root", scan_type="ack")

        conf.verb = 0
        pkt = IP(dst=target)/TCP(dport=port, flags="A", seq=0)

        try:
            resp = sr1(pkt, timeout=self.timeout, verbose=0)

            if resp is None:
                return StealthResult(port=port, state="filtered", scan_type="ack")

            if resp.haslayer(TCP):
                flags = resp[TCP].flags
                if flags & 0x04:
                    return StealthResult(port=port, state="unfiltered", scan_type="ack")

            return StealthResult(port=port, state="filtered", scan_type="ack")

        except Exception:
            return StealthResult(port=port, state="error", scan_type="ack")

    def _sync_fragment_scan(self, target: str, port: int) -> List[StealthResult]:
        if not self.is_available():
            return [StealthResult(port=port, state="requires_root", scan_type="fragment")]
        
        conf.verb = 0
        results = []
        
        for i in range(3):
            pkt = IP(dst=target, frag=i*8)/TCP(dport=port, flags="S", seq=1000)
            frags = fragment(pkt, fragsize=8)
            
            try:
                resp = sr1(frags[0], timeout=self.timeout, verbose=0)
                
                if resp and resp.haslayer(TCP):
                    flags = resp[TCP].flags
                    if flags == 0x12:
                        results.append(StealthResult(port=port, state="open", scan_type="fragment"))
                    elif flags & 0x04:
                        results.append(StealthResult(port=port, state="closed", scan_type="fragment"))
                    else:
                        results.append(StealthResult(port=port, state="filtered", scan_type="fragment"))
                else:
                    results.append(StealthResult(port=port, state="filtered", scan_type="fragment"))
            except Exception:
                results.append(StealthResult(port=port, state="error", scan_type="fragment"))
        
        return results

    def _sync_decoy_scan(self, target: str, port: int) -> StealthResult:
        if not self.is_available():
            return StealthResult(port=port, state="requires_root", scan_type="decoy")
        
        conf.verb = 0
        real_ip = str(RandIP())
        
        decoy_ips = [str(RandIP()) for _ in range(self.decoy_count - 1)]
        
        decoy_ips.insert(random.randint(0, len(decoy_ips)), real_ip)
        
        for src_ip in decoy_ips:
            pkt = IP(src=src_ip, dst=target)/TCP(dport=port, flags="S", seq=1000)
            try:
                sr1(pkt, timeout=1, verbose=0)
            except Exception:
                pass
        
        pkt = IP(dst=target)/TCP(dport=port, flags="S", seq=1000)
        try:
            resp = sr1(pkt, timeout=self.timeout, verbose=0)
            
            if resp is None:
                return StealthResult(port=port, state="filtered|open", scan_type="decoy")
            
            if resp.haslayer(TCP):
                flags = resp[TCP].flags
                if flags == 0x12:
                    return StealthResult(port=port, state="open", scan_type="decoy")
                elif flags & 0x04:
                    return StealthResult(port=port, state="closed", scan_type="decoy")
            
            return StealthResult(port=port, state="filtered", scan_type="decoy")
            
        except Exception:
            return StealthResult(port=port, state="error", scan_type="decoy")

    async def scan(
        self,
        target: str,
        ports: List[int],
        scan_type: str = "fin",
        progress_callback: Optional[callable] = None
    ) -> List[StealthResult]:
        if not self.is_available():
            return [StealthResult(port=p, state="requires_root", scan_type=scan_type) for p in ports]
        
        loop = asyncio.get_event_loop()
        results = []
        total = len(ports)
        
        for i, port in enumerate(ports):
            if scan_type == "fin":
                result = await loop.run_in_executor(self._executor, self._sync_fin_scan, target, port)
            elif scan_type == "null":
                result = await loop.run_in_executor(self._executor, self._sync_null_scan, target, port)
            elif scan_type == "xmas":
                result = await loop.run_in_executor(self._executor, self._sync_xmas_scan, target, port)
            elif scan_type == "fragment":
                result_list = await loop.run_in_executor(self._executor, self._sync_fragment_scan, target, port)
                result = result_list[0] if result_list else StealthResult(port=port, state="error", scan_type="fragment")
            elif scan_type == "decoy":
                result = await loop.run_in_executor(self._executor, self._sync_decoy_scan, target, port)
            elif scan_type == "ack":
                result = await loop.run_in_executor(self._executor, self._sync_ack_scan, target, port)
            else:
                result = StealthResult(port=port, state="unknown", scan_type=scan_type)
            
            results.append(result)
            
            if progress_callback:
                progress_callback(i + 1, total)
            
            await asyncio.sleep(0.01)
        
        return results
