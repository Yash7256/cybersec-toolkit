"""
Concurrency stress test.
Tests multiple simultaneous scans and rate limiting.
"""
import asyncio
import time
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from cybersec.core.scanner import AsyncPortScanner
from cybersec.core.metrics import StressTestMetrics


async def scan_target(target: str, port_range: str, scan_id: int):
    """Run a single scan."""
    scanner = AsyncPortScanner(timeout=1.0)
    report = await scanner.scan(target, port_range)
    return scan_id, report


async def run_concurrency_test():
    """Run multiple concurrent scans."""
    print("=" * 60)
    print("CONCURRENCY STRESS TEST")
    print("=" * 60)
    
    # Test 1: 5 concurrent scans of different targets
    targets = [
        ("scanme.nmap.org", "22,80,443"),
        ("scanme.nmap.org", "21,25,53"),
        ("scanme.nmap.org", "110,143,993"),
        ("scanme.nmap.org", "995,3306,5432"),
        ("scanme.nmap.org", "6379,8080,8443"),
    ]
    
    print(f"\n[1] Running {len(targets)} concurrent scans...")
    start = time.time()
    
    tasks = [
        scan_target(target, ports, i) 
        for i, (target, ports) in enumerate(targets)
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    end = time.time()
    duration = end - start
    
    print(f"\n[2] RESULTS ({duration:.2f}s total):")
    
    total_ports = 0
    total_open = 0
    for i, result in enumerate(results):
        if isinstance(result, Exception):
            print(f"    Scan {i}: ERROR - {result}")
        else:
            scan_id, report = result
            ports = len(report.open_ports)
            total_ports += 15  # 5 ports per scan
            total_open += ports
            print(f"    Scan {scan_id}: {ports} open ports")
    
    print(f"\n[3] AGGREGATE:")
    print(f"    Total port attempts: {total_ports}")
    print(f"    Total open found: {total_open}")
    print(f"    Avg time per scan: {duration/len(targets):.2f}s")
    print(f"    Scans per second: {len(targets)/duration:.2f}")
    
    # Test 2: High concurrency (100 parallel connections to same target)
    print("\n[4] HIGH CONCURRENCY TEST (100 parallel to same target)...")
    
    # Note: This uses the scanner's internal semaphore, not asyncio parallel
    fast_scanner = AsyncPortScanner(timeout=1.0, rate_preset="aggressive")
    report = await fast_scanner.scan("scanme.nmap.org", "1-100")
    
    if fast_scanner.metrics:
        m = fast_scanner.metrics.export_metrics()
        print(f"\n[5] HIGH CONCURRENCY METRICS:")
        print(f"    Total ports: {m['counters']['total_ports_scanned']}")
        print(f"    Success: {m['counters']['successful_connections']}")
        print(f"    Failed: {m['counters']['failed_connections']}")
        print(f"    Ports/sec: {m['computed']['ports_per_second']:.2f}")
        print(f"    FDs: {m['system']['open_file_descriptors']}")
    
    print("\n" + "=" * 60)


if __name__ == "__main__":
    asyncio.run(run_concurrency_test())