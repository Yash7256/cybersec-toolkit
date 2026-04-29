#!/usr/bin/env python3
"""
Scan a single target with configurable parameters.
Usage:
    python tests/scan_target.py --target scanme.nmap.org --ports 1-65535
"""
import argparse
import asyncio
import json
import time
from typing import List, Optional

from cybersec.core.scanner import AsyncPortScanner


def parse_ports(ports_str: str) -> List[int]:
    """Parse port range string into list of ports."""
    ports = []
    for part in ports_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return ports


def port_result_to_dict(port_result) -> dict:
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
        "risk": port_result.risk.risk_level if port_result.risk else None,
        "cves": [c.id for c in (port_result.cves or [])],
    }


async def run_scan(
    target: str,
    ports: List[int],
    concurrency: int = 100,
    timeout: float = 2.0,
    retries: int = 0,
) -> dict:
    """Run a scan on the given target."""
    scanner = AsyncPortScanner(timeout=timeout, enable_connection_pool=True, retries=retries)

    ports_str = ",".join(map(str, ports[:10000]))

    start_time = time.time()
    report = await scanner.scan(
        target=target,
        port_range=ports_str,
        resolved_ip=target,
    )
    scan_duration = time.time() - start_time

    results = [port_result_to_dict(p) for p in report.open_ports]

    return {
        "target": target,
        "ip": report.ip,
        "scan_parameters": {
            "ports_specified": len(ports),
            "ports_scanned": report.total_ports_scanned,
            "concurrency": concurrency,
            "timeout": timeout,
            "retries": retries,
        },
        "performance": {
            "scan_duration_seconds": round(scan_duration, 2),
            "ports_per_second": round(report.total_ports_scanned / scan_duration, 2) if scan_duration > 0 else 0,
            "avg_latency_ms": report.avg_latency_ms,
            "peak_concurrency": report.peak_concurrency,
        },
        "results": results,
        "summary": {
            "total_open": len(results),
            "open_ports": [r["port"] for r in results],
        },
    }


async def main():
    parser = argparse.ArgumentParser(description="Scan a target with CyberSec")
    parser.add_argument("--target", required=True, help="Target host or IP")
    parser.add_argument("--ports", required=True, help="Port range (e.g., '1-1000', '80,443,8080')")
    parser.add_argument("--concurrency", type=int, default=100, help="Max concurrent connections")
    parser.add_argument("--timeout", type=float, default=2.0, help="Connection timeout in seconds")
    parser.add_argument("--retries", type=int, default=0, help="Number of retries")
    parser.add_argument("--output", default="scan_result.json", help="Output file")
    parser.add_argument("--format", choices=["json", "summary"], default="summary", help="Output format")

    args = parser.parse_args()

    ports = parse_ports(args.ports)
    print(f"\n{'='*60}")
    print(f"  CyberSec Scanner")
    print(f"  Target: {args.target}")
    print(f"  Ports: {len(ports)} (spec: {args.ports})")
    print(f"  Concurrency: {args.concurrency}")
    print(f"  Timeout: {args.timeout}s")
    print(f"{'='*60}\n")

    result = await run_scan(
        target=args.target,
        ports=ports,
        concurrency=args.concurrency,
        timeout=args.timeout,
        retries=args.retries,
    )

    if args.format == "json":
        with open(args.output, "w") as f:
            json.dump(result, f, indent=2, default=str)
        print(f"Results saved to: {args.output}")
    else:
        print(f"\n{'='*60}")
        print("  SCAN RESULTS")
        print(f"{'='*60}")
        print(f"  Duration: {result['performance']['scan_duration_seconds']}s")
        print(f"  Throughput: {result['performance']['ports_per_second']} ports/sec")
        print(f"  Peak Concurrency: {result['performance']['peak_concurrency']}")
        print(f"\n  Open Ports ({len(result['summary']['open_ports'])}):")
        for r in result["results"]:
            svc = r.get("service", {}) or {}
            svc_name = svc.get("name", "unknown")
            banner = svc.get("banner", "")
            banner_preview = banner[:40] if banner else ""
            print(f"    :{r['port']} - {svc_name} {banner_preview}")
        print(f"\n{'='*60}")

        with open(args.output, "w") as f:
            json.dump(result, f, indent=2, default=str)
        print(f"Full results saved to: {args.output}")


if __name__ == "__main__":
    asyncio.run(main())