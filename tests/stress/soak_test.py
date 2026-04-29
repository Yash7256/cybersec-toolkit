"""
Soak test.
Extended duration test to find memory leaks and stability issues.
"""
import asyncio
import time
import sys
import gc
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from cybersec.core.scanner import AsyncPortScanner
from cybersec.core.metrics import StressTestMetrics


async def run_soak_test(duration_seconds: int = 60, target: str = "scanme.nmap.org"):
    """
    Run scanner continuously for extended period.
    
    Args:
        duration_seconds: How long to run
        target: Target to scan
    """
    print("=" * 60)
    print("SOAK TEST")
    print(f"Duration: {duration_seconds}s")
    print(f"Target: {target}")
    print("=" * 60)
    
    metrics_history = []
    scanner = AsyncPortScanner(timeout=1.0, rate_preset="normal")
    
    port_ranges = ["1-100", "1-500", "common", "22,80,443,8080,8443"]
    
    iteration = 0
    start_time = time.time()
    last_report = time.time()
    
    total_open_ports = 0
    total_scan_duration = 0
    
    print(f"\n[1] Starting soak test...")
    
    try:
        while time.time() - start_time < duration_seconds:
            iteration += 1
            
            # Rotate through port ranges
            port_range = port_ranges[(iteration - 1) % len(port_ranges)]
            
            # Run scan
            scan_start = time.time()
            try:
                report = await scanner.scan(target, port_range)
            except Exception as e:
                print(f"\n    ERROR on iteration {iteration}: {e}")
                continue
            
            scan_duration = time.time() - scan_start
            total_scan_duration += scan_duration
            
            # Get metrics
            if scanner.metrics:
                m = scanner.metrics.export_metrics()
                metrics_history.append(m)
                
                ports = len(report.open_ports)
                total_open_ports += ports
                
                pps = m["computed"]["ports_per_second"]
                error_rate = m["computed"]["error_rate"]
                mem_mb = m["system"]["memory_mb"]
                
                # Progress every 10 iterations
                if iteration % 10 == 0:
                    elapsed = time.time() - start_time
                    print(f"    [{iteration}] {elapsed:.0f}s: {ports} open, {pps:.1f} pps, {mem_mb:.1f} MB")
                
                # Reset metrics for next iteration
                scanner.metrics.reset()
            
            # Small delay between scans
            await asyncio.sleep(0.5)
        
    except KeyboardInterrupt:
        print("\n    Interrupted by user")
    
    total_time = time.time() - start_time
    
    print(f"\n[2] SOAK TEST COMPLETE")
    print(f"    Iterations: {iteration}")
    print(f"    Total time: {total_time:.2f}s")
    print(f"    Total open ports: {total_open_ports}")
    print(f"    Avg scan time: {total_scan_duration/iteration:.2f}s")
    print(f"    Iterations/sec: {iteration/total_time:.2f}")
    
    # Analyze memory trend
    if metrics_history:
        mem_values = [m["system"]["memory_mb"] for m in metrics_history]
        first_mem = mem_values[0]
        last_mem = mem_values[-1]
        mem_growth = last_mem - first_mem
        
        print(f"\n[3] MEMORY ANALYSIS:")
        print(f"    First: {first_mem:.2f} MB")
        print(f"    Last: {last_mem:.2f} MB")
        print(f"    Growth: {mem_growth:+.2f} MB")
        
        if mem_growth > 50:
            print("    [WARNING] Significant memory growth detected!")
    
    # Analyze error rate trend
    if metrics_history:
        error_rates = [m["computed"]["error_rate"] for m in metrics_history]
        avg_error = sum(error_rates) / len(error_rates)
        
        print(f"\n[4] ERROR RATE ANALYSIS:")
        print(f"    Average: {avg_error:.2f}%")
        print(f"    Min: {min(error_rates):.2f}%")
        print(f"    Max: {max(error_rates):.2f}%")
    
    # Check for file descriptor leak
    if metrics_history:
        fd_values = [m["system"]["open_file_descriptors"] for m in metrics_history]
        first_fd = fd_values[0]
        last_fd = fd_values[-1]
        
        print(f"\n[5] FILE DESCRIPTOR ANALYSIS:")
        print(f"    First: {first_fd}")
        print(f"    Last: {last_fd}")
        print(f"    Growth: {last_fd - first_fd:+d}")
        
        if (last_fd - first_fd) > 50:
            print("    [WARNING] Possible FD leak detected!")
    
    print("\n" + "=" * 60)
    
    return {
        "iterations": iteration,
        "total_time": total_time,
        "total_open_ports": total_open_ports,
        "memory_growth": mem_growth if metrics_history else 0,
    }


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Soak test")
    parser.add_argument("-d", "--duration", type=int, default=60, help="Duration in seconds")
    parser.add_argument("-t", "--target", type=str, default="scanme.nmap.org", help="Target host")
    args = parser.parse_args()
    
    asyncio.run(run_soak_test(args.duration, args.target))