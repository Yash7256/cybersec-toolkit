#!/usr/bin/env python3
"""
Scan Docker container targets and save results.
"""
import asyncio
import json
import os
from typing import Dict, Any

from cybersec.core.scanner import AsyncPortScanner

TARGETS = {
    "docker_nginx": ("172.23.0.2", [80, 443]),
    "docker_redis": ("172.23.0.7", [6379]),
    "docker_postgres": ("172.23.0.6", [5432]),
    "docker_api": ("172.23.0.4", [8000]),
    "docker_tarpit": ("172.23.0.3", [9999]),
    "docker_filtered": ("172.23.0.5", [8888, 8889]),
}


def port_result_to_dict(port_result) -> Dict[str, Any]:
    """Convert PortResult to dict for JSON serialization."""
    si = port_result.service
    return {
        "port": port_result.port,
        "protocol": port_result.protocol,
        "state": port_result.state,
        "service": {
            "name": si.name if si else None,
            "confidence": si.confidence if si else None,
            "product": si.product if si and hasattr(si, 'product') else None,
            "version": si.version if si and hasattr(si, 'version') else None,
            "banner": si.banner if si else None,
        } if si else None,
    }


def scan_report_to_dict(report) -> Dict[str, Any]:
    """Convert ScanReport to dict for JSON serialization."""
    return {
        "target": report.target,
        "ip": report.ip,
        "total_ports_scanned": report.total_ports_scanned,
        "open_ports": [port_result_to_dict(p) for p in report.open_ports],
        "scan_duration": report.scan_duration,
        "avg_latency_ms": report.avg_latency_ms,
    }


async def run_scan(host: str, ports: list) -> Dict[str, Any]:
    """Run a scan on the given host and ports."""
    scanner = AsyncPortScanner(timeout=3.0, enable_connection_pool=True)
    ports_str = ",".join(map(str, ports))
    
    report = await scanner.scan(
        target=host,
        port_range=ports_str,
        resolved_ip=host
    )
    
    return scan_report_to_dict(report)


async def main():
    results_dir = os.path.join(os.path.dirname(__file__), "results")
    os.makedirs(results_dir, exist_ok=True)
    
    print("Scanning Docker targets...")
    print("=" * 60)
    
    for name, (host, ports) in TARGETS.items():
        print(f"\n[{name}] Scanning {host}:{ports}...")
        
        try:
            result = await run_scan(host, ports)
            
            output_path = os.path.join(results_dir, f"{name}.json")
            with open(output_path, "w") as f:
                json.dump(result, f, indent=2)
            
            open_ports = result["open_ports"]
            print(f"  Found {len(open_ports)} open ports:")
            for p in open_ports:
                svc = p["service"]
                svc_name = svc["name"] if svc else "unknown"
                banner = svc["banner"][:40] if svc and svc["banner"] else None
                print(f"    :{p['port']} - {svc_name} {banner or ''}")
            
            print(f"  Results saved to: {output_path}")
            
        except Exception as e:
            print(f"  ERROR: {e}")
    
    print("\n" + "=" * 60)
    print("Scan complete!")


if __name__ == "__main__":
    asyncio.run(main())