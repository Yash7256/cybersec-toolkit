"""
Idle/Zombie scan module for source IP obfuscation.
Requires root privileges and a zombie host with predictable IP ID behavior.
"""
import os
import asyncio
import time
from dataclasses import dataclass
from typing import List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor

try:
    from scapy.all import IP, TCP, sr1, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

@dataclass
class ZombieResult:
    target_port: int
    state: str
    protocol: str = "tcp"
    zombie_ip: Optional[str] = None
    ip_id_delta: Optional[int] = None

def is_root() -> bool:
    return os.geteuid() == 0 if hasattr(os, 'geteuid') else False

class ZombieScanner:
    def __init__(self, zombie_ip: str, timeout: float = 3.0, probe_port: int = 80):
        self.zombie_ip = zombie_ip
        self.timeout = timeout
        self.probe_port = probe_port
        self._executor = ThreadPoolExecutor(max_workers=5)
        self._has_root = is_root()

    def is_available(self) -> bool:
        return SCAPY_AVAILABLE and self._has_root

    def verify_zombie(self) -> Tuple[bool, str]:
        if not self.is_available():
            return False, "Root privileges or Scapy not available"
        
        conf.verb = 0
        ip_ids = []
        
        for _ in range(6):
            pkt = IP(dst=self.zombie_ip)/TCP(dport=self.probe_port, flags="S")
            try:
                resp = sr1(pkt, timeout=self.timeout, verbose=0)
                if resp and resp.haslayer(IP) and resp.haslayer(TCP):
                    if resp[TCP].flags & 0x04:
                        return False, f"Zombie port {self.probe_port} is closed"
                    ip_ids.append(resp[IP].id)
                else:
                    ip_ids.append(0)
            except Exception:
                ip_ids.append(0)
            time.sleep(0.2)
        
        if len(ip_ids) < 4:
            return False, "Not enough IP ID samples collected"
        
        diffs = [ip_ids[i+1] - ip_ids[i] for i in range(len(ip_ids)-1)]
        
        all_sequential = all(1 <= d <= 5 for d in diffs)
        if all_sequential:
            return True, "Zombie verified - sequential IP ID behavior"
        
        all_zero = all(d == 0 for d in diffs)
        if all_zero:
            return True, "Zombie verified - zero IP ID behavior (Linux with DF)"
        
        return False, f"IP ID pattern not predictable: {diffs}"

    def _sync_probe_zombie(self) -> Optional[int]:
        if not self.is_available():
            return None
        
        conf.verb = 0
        pkt = IP(dst=self.zombie_ip)/TCP(dport=self.probe_port, flags="S")
        
        try:
            resp = sr1(pkt, timeout=self.timeout, verbose=0)
            if resp and resp.haslayer(IP):
                rst = IP(dst=self.zombie_ip)/TCP(dport=self.probe_port, flags="R", seq=resp[TCP].ack)
                sr1(rst, timeout=1, verbose=0)
                return resp[IP].id
        except Exception:
            pass
        return None

    def _sync_spoofed_probe(self, target: str, port: int) -> bool:
        if not self.is_available():
            return False
        
        conf.verb = 0
        pkt = IP(src=self.zombie_ip, dst=target)/TCP(dport=port, flags="S", seq=1000)
        
        try:
            sr1(pkt, timeout=self.timeout, verbose=0)
            return True
        except Exception:
            return False

    def _sync_idle_scan(self, target: str, target_port: int) -> ZombieResult:
        if not self.is_available():
            return ZombieResult(target_port=target_port, state="requires_root", zombie_ip=self.zombie_ip)
        
        conf.verb = 0
        
        id1 = self._sync_probe_zombie()
        if id1 is None:
            return ZombieResult(target_port=target_port, state="zombie_unreachable", zombie_ip=self.zombie_ip)
        
        if not self._sync_spoofed_probe(target, target_port):
            return ZombieResult(target_port=target_port, state="probe_failed", zombie_ip=self.zombie_ip)
        
        id2 = self._sync_probe_zombie()
        if id2 is None:
            return ZombieResult(target_port=target_port, state="zombie_unreachable", zombie_ip=self.zombie_ip)
        
        delta = id2 - id1
        
        if delta >= 2:
            return ZombieResult(
                target_port=target_port,
                state="open",
                zombie_ip=self.zombie_ip,
                ip_id_delta=delta
            )
        elif delta == 1:
            return ZombieResult(
                target_port=target_port,
                state="closed|filtered",
                zombie_ip=self.zombie_ip,
                ip_id_delta=delta
            )
        else:
            return ZombieResult(
                target_port=target_port,
                state="unknown",
                zombie_ip=self.zombie_ip,
                ip_id_delta=delta
            )

    async def scan_port(self, target: str, port: int) -> ZombieResult:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(self._executor, self._sync_idle_scan, target, port)

    async def scan(
        self,
        target: str,
        ports: List[int],
        progress_callback: Optional[callable] = None
    ) -> List[ZombieResult]:
        if not self.is_available():
            return [ZombieResult(target_port=p, state="requires_root", zombie_ip=self.zombie_ip) for p in ports]
        
        is_valid, message = self.verify_zombie()
        if not is_valid:
            return [ZombieResult(target_port=p, state=f"zombie_invalid: {message}", zombie_ip=self.zombie_ip) for p in ports]
        
        results = []
        total = len(ports)
        
        for i, port in enumerate(ports):
            result = await self.scan_port(target, port)
            results.append(result)
            
            if progress_callback:
                progress_callback(i + 1, total)
            
            await asyncio.sleep(0.1)
        
        return results
