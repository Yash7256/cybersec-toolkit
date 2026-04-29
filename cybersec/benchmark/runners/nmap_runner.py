import nmap
import time
import asyncio
from typing import Dict, Any, List
from cybersec.benchmark.runners.base import ScannerRunner

class NmapRunner(ScannerRunner):
    def __init__(self):
        super().__init__("Nmap")

    async def scan(self, target_ip: str, ports: List[int]) -> Dict[str, Any]:
        ports_str = ",".join(map(str, ports))
        
        start_time = time.monotonic()
        try:
            loop = asyncio.get_event_loop()
            scanner = nmap.PortScanner()
            
            def do_scan():
                scanner.scan(target_ip, ports_str, arguments='-Pn -n -T4 --max-retries 1 --host-timeout 10s -sV')
                return scanner
                
            scanner = await loop.run_in_executor(None, do_scan)
            scan_time = time.monotonic() - start_time
            
            results = {}
            for p in ports:
                results[str(p)] = {"state": "closed"}
            
            if target_ip in scanner.all_hosts():
                if 'tcp' in scanner[target_ip]:
                    for port, port_data in scanner[target_ip]['tcp'].items():
                        results[str(port)] = {
                            "state": port_data['state'],
                            "service": port_data.get('name', 'unknown'),
                            "product": port_data.get('product'),
                            "version": port_data.get('version'),
                        }
            
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