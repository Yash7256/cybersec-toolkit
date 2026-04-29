import time
import asyncio
from typing import Dict, Any, List
from cybersec.benchmark.runners.base import ScannerRunner
from cybersec.core.scanner import AsyncPortScanner

class CyberSecRunner(ScannerRunner):
    def __init__(self):
        super().__init__("CyberSecScanner")

    async def scan(self, target_ip: str, ports: List[int]) -> Dict[str, Any]:
        scanner = AsyncPortScanner(timeout=1.0, enable_connection_pool=True)
        ports_str = ",".join(map(str, ports))
        
        start_time = time.monotonic()
        try:
            report = await scanner.scan(target=target_ip, port_range=ports_str, resolved_ip=target_ip)
            scan_time = time.monotonic() - start_time
            
            results = {}
            for p in ports:
                port_str = str(p)
                found = next((x for x in report.open_ports if x.port == p), None)
                if found:
                    si = found.service
                    results[port_str] = {
                        "state": "open",
                        "service": si.name if si else "unknown",
                        "product": si.product if si and hasattr(si, 'product') else None,
                        "version": si.version if si and hasattr(si, 'version') else None,
                    }
                else:
                    results[port_str] = {"state": "closed"}
                    
            return {
                "results": results,
                "scan_time": scan_time,
                "error": None
            }
        except Exception as e:
            return {
                "results": {},
                "scan_time": time.monotonic() - start_time,
                "error": str(e)
            }
