"""
Full port range stress test (1-65535).
Tests scanner under maximum load.
"""
import asyncio
import time
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from cybersec.core.scanner import AsyncPortScanner


async def run_full_scan():
    """Scan all 65535 ports."""
    print("=" * 60)
    print("FULL PORT RANGE STRESS TEST")
    print("Target: scanme.nmap.org, Ports: 1-65535")
    print("=" * 60)
    
    scanner = AsyncPortScanner(timeout=2.0, rate_preset="aggressive")
    
    print("\n[1] Starting full port scan...")
    start = time.time()
    
    try:
        report = await scanner.scan("scanme.nmap.org", "1-65535")
    except Exception as e:
        print(f"Scan error: {e}")
        return
    
    end = time.time()
    duration = end - start
    
    # Get metrics from scan report (not scanner.metrics)
    metrics = report.metrics if report.metrics else None
    
    print(f"\n[2] SCAN COMPLETE")
    print(f"    Duration: {duration:.2f}s")
    print(f"    Open ports: {len(report.open_ports)}")
    
    if metrics:
        port_states = metrics.get('port_states', {})
        total = metrics['counters']['total_ports_scanned']
        
        open_ports = port_states.get('open', 0)
        closed_ports = port_states.get('closed', 0)
        filtered = port_states.get('filtered', 0)
        timeouts = port_states.get('timeout', 0)
        error = port_states.get('error', 0)
        unreachable = port_states.get('unreachable', 0)
        
        reachable = open_ports + closed_ports
        reachable_pct = (reachable / total * 100) if total > 0 else 0
        filtered_pct = (filtered / total * 100) if total > 0 else 0
        
        print(f"\n[3] PORT STATES:")
        print(f"    Total scanned: {metrics['counters']['total_ports_scanned']}")
        print(f"    Open ports: {open_ports}")
        print(f"    Closed ports: {closed_ports}")
        print(f"    Filtered: {filtered}")
        print(f"    Timeouts: {timeouts}")
        print(f"    Errors: {error}")
        print(f"    Unreachable: {unreachable}")
        
        print(f"\n[4] DETECTION COVERAGE:")
        print(f"    Reachable (open+closed): {reachable_pct:.2f}%")
        print(f"    Filtered ratio: {filtered_pct:.2f}%")
        
        print(f"\n[5] PERFORMANCE:")
        print(f"    Ports per second: {metrics['computed']['ports_per_second']:.2f}")
        print(f"\n[6] SYSTEM:")
        print(f"    CPU: {metrics['system']['cpu_percent']:.2f}%")
        print(f"    Memory: {metrics['system']['memory_mb']:.2f} MB")
        print(f"    FDs: {metrics['system']['open_file_descriptors']}")
    else:
        print("\n[ERROR] No metrics in report!")
    
    print("\n" + "=" * 60)
    
    return metrics


if __name__ == "__main__":
    asyncio.run(run_full_scan())