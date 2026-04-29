#!/usr/bin/env python3
"""
API Soak Test - Sustained Load.
Runs sustained load for 30 minutes with metrics tracking.
"""
import asyncio
import argparse
import time
import csv
import os
import sys
from datetime import datetime
from typing import Optional

import httpx

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


API_BASE = "http://localhost:8000/api"
OUTPUT_FILE = "soak_test_results.csv"


class SoakTest:
    """Sustained load soak test."""
    
    def __init__(self, api_base: str, output_file: str):
        self.api_base = api_base
        self.output_file = output_file
        self.results: list[dict] = []
        self.scan_count = 0
        self.error_count = 0
        
        self.process = None
        if PSUTIL_AVAILABLE:
            try:
                self.process = psutil.Process()
            except Exception:
                pass
    
    async def check_api(self) -> bool:
        """Check API availability."""
        try:
            async with httpx.AsyncClient() as client:
                r = await client.get(f"{self.api_base}/scans/health")
                return r.status_code == 200
        except Exception:
            return False
    
    async def submit_scan(self, client: httpx.AsyncClient) -> Optional[str]:
        """Submit scan request."""
        try:
            r = await client.post(
                f"{self.api_base}/scans/",
                json={
                    "target": "scanme.nmap.org",
                    "port_range": "top100",
                    "scan_type": "connect",
                    "timeout": 3.0
                },
                timeout=15.0
            )
            if r.status_code == 200:
                data = r.json()
                return data.get("id") or data.get("scan_id")
        except Exception:
            pass
        return None
    
    async def wait_for_completion(
        self, 
        client: httpx.AsyncClient,
        scan_id: str,
        max_wait: int = 60
    ) -> bool:
        """Wait for scan to complete."""
        for _ in range(max_wait):
            try:
                r = await client.get(f"{self.api_base}/scans/{scan_id}/status")
                status = r.json().get("status")
                if status == "completed":
                    return True
                if status == "failed":
                    return False
                await asyncio.sleep(1)
            except Exception:
                pass
        return False
    
    async def get_results(self, client: httpx.AsyncClient, scan_id: str) -> Optional[dict]:
        """Get scan results with metrics."""
        try:
            r = await client.get(f"{self.api_base}/scans/{scan_id}")
            if r.status_code == 200:
                return r.json()
        except Exception:
            pass
        return None
    
    def get_system_metrics(self) -> dict:
        """Get system CPU and memory."""
        cpu = 0.0
        memory_mb = 0.0
        
        if self.process:
            try:
                cpu = self.process.cpu_percent(interval=0.1)
                mem = self.process.memory_info()
                memory_mb = mem.rss / (1024 * 1024)
            except Exception:
                pass
        
        return {
            "cpu_percent": cpu,
            "memory_mb": memory_mb
        }
    
    def save_csv(self):
        """Save results to CSV."""
        if not self.results:
            return
        
        fieldnames = [
            "timestamp",
            "scan_num",
            "total_ports_scanned",
            "successful_connections",
            "failed_connections",
            "error_rate",
            "ports_per_second",
            "cpu_percent",
            "memory_mb",
            "open_file_descriptors"
        ]
        
        with open(self.output_file, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for row in self.results:
                writer.writerow(row)
        
        print(f"Results saved to {self.output_file}")
    
    async def run_single_scan(self, client: httpx.AsyncClient) -> Optional[dict]:
        """Run single scan and collect metrics."""
        
        scan_id = await self.submit_scan(client)
        
        if not scan_id:
            self.error_count += 1
            return None
        
        done = await self.wait_for_completion(client, scan_id)
        
        if not done:
            self.error_count += 1
            return None
        
        results = await self.get_results(client, scan_id)
        
        if not results or "metrics" not in results:
            self.error_count += 1
            return None
        
        return results["metrics"]
    
    async def run_soak_test(
        self,
        duration_minutes: int = 30,
        interval_seconds: int = 5
    ) -> dict:
        """Run soak test for specified duration."""
        
        print("=" * 60)
        print("API SOAK TEST - SUSTAINED LOAD")
        print(f"Duration: {duration_minutes} minutes")
        print(f"Scan interval: {interval_seconds} seconds")
        print("=" * 60)
        
        # Initialize CSV
        with open(self.output_file, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "timestamp", "scan_num", "total_ports_scanned",
                "successful_connections", "failed_connections", "error_rate",
                "ports_per_second", "cpu_percent", "memory_mb",
                "open_file_descriptors"
            ])
        
        start_time = time.time()
        end_time = start_time + (duration_minutes * 60)
        next_scan_time = start_time
        minute_count = 0
        
        async with httpx.AsyncClient() as client:
            while time.time() < end_time:
                self.scan_count += 1
                current_time = time.time()
                
                # Run scan
                print(f"\n[{self.scan_count}] Running scan...", end=" ", flush=True)
                
                metrics = await self.run_single_scan(client)
                
                sys_metrics = self.get_system_metrics()
                
                if metrics:
                    counters = metrics.get("counters", {})
                    computed = metrics.get("computed", {})
                    system = metrics.get("system", {})
                    
                    result = {
                        "timestamp": datetime.now().isoformat(),
                        "scan_num": self.scan_count,
                        "total_ports_scanned": counters.get("total_ports_scanned", 0),
                        "successful_connections": counters.get("successful_connections", 0),
                        "failed_connections": counters.get("failed_connections", 0),
                        "error_rate": computed.get("error_rate", 0),
                        "ports_per_second": computed.get("ports_per_second", 0),
                        "cpu_percent": system.get("cpu_percent", sys_metrics["cpu_percent"]),
                        "memory_mb": system.get("memory_mb", sys_metrics["memory_mb"]),
                        "open_file_descriptors": system.get("open_file_descriptors", 0)
                    }
                    
                    self.results.append(result)
                    
                    # Save to CSV immediately
                    with open(self.output_file, "a", newline="") as f:
                        writer = csv.writer(f)
                        writer.writerow([
                            result["timestamp"],
                            result["scan_num"],
                            result["total_ports_scanned"],
                            result["successful_connections"],
                            result["failed_connections"],
                            result["error_rate"],
                            result["ports_per_second"],
                            result["cpu_percent"],
                            result["memory_mb"],
                            result["open_file_descriptors"]
                        ])
                    
                    print(
                        f"OK - {result['total_ports_scanned']} ports, "
                        f"{result['ports_per_second']:.1f} pps, "
                        f"{result['memory_mb']:.1f} MB"
                    )
                else:
                    print("FAILED")
                
                # Log every minute
                elapsed = current_time - start_time
                if elapsed >= (minute_count + 1) * 60:
                    minute_count += 1
                    print(f"\n--- MINUTE {minute_count} ---")
                    
                    if self.results:
                        recent = self.results[-10:]  # Last 10 scans
                        
                        avg_pps = sum(r["ports_per_second"] for r in recent) / len(recent)
                        avg_memory = sum(r["memory_mb"] for r in recent) / len(recent)
                        avg_error = sum(r["error_rate"] for r in recent) / len(recent)
                        
                        print(
                            f"  CPU: {sys_metrics['cpu_percent']:.1f}%, "
                            f"Memory: {sys_metrics['memory_mb']:.1f} MB, "
                            f"Error: {avg_error:.1f}%"
                        )
                
                # Wait for next scan
                next_scan_time += interval_seconds
                sleep_time = next_scan_time - time.time()
                if sleep_time > 0 and time.time() < end_time:
                    await asyncio.sleep(sleep_time)
        
        # Final summary
        return self.analyze_results()
    
    def analyze_results(self) -> dict:
        """Analyze results for leaks and degradation."""
        
        if len(self.results) < 2:
            return {"status": "insufficient_data"}
        
        first_10 = self.results[:10]
        last_10 = self.results[-10:]
        
        first_pps = sum(r["ports_per_second"] for r in first_10) / len(first_10)
        last_pps = sum(r["ports_per_second"] for r in last_10) / len(last_10)
        
        first_mem = sum(r["memory_mb"] for r in first_10) / len(first_10)
        last_mem = sum(r["memory_mb"] for r in last_10) / len(last_10)
        
        first_error = sum(r["error_rate"] for r in first_10) / len(first_10)
        last_error = sum(r["error_rate"] for r in last_10) / len(last_10)
        
        issues = []
        
        # Check memory leak
        mem_growth = last_mem - first_mem
        if mem_growth > 100:
            issues.append(f"MEMORY LEAK: +{mem_growth:.1f} MB")
        
        # Check performance degradation
        pps_drop = first_pps - last_pps
        if pps_drop > 20:
            issues.append(f"PERF DEGRADATION: -{pps_drop:.1f} pps")
        
        # Check error rate spike
        error_change = last_error - first_error
        if abs(error_change) > 10:
            issues.append(f"ERROR RATE CHANGE: {error_change:+.1f}%")
        
        return {
            "total_scans": self.scan_count,
            "total_errors": self.error_count,
            "first_10_avg_pps": first_pps,
            "last_10_avg_pps": last_pps,
            "pps_change": pps_drop,
            "first_10_avg_mem": first_mem,
            "last_10_avg_mem": last_mem,
            "mem_growth": mem_growth,
            "issues": issues,
            "status": "FAIL" if issues else "PASS"
        }


async def main(
    duration_minutes: int = 30,
    interval_seconds: int = 5,
    api_base: str = API_BASE,
    output_file: str = OUTPUT_FILE
):
    """Main entry point."""
    
    test = SoakTest(api_base, output_file)
    
    if not await test.check_api():
        print("ERROR: API not available")
        return
    
    print("API OK\n")
    
    result = await test.run_soak_test(duration_minutes, interval_seconds)
    
    # Print analysis
    print("\n" + "=" * 60)
    print("SOAK TEST ANALYSIS")
    print("=" * 60)
    
    print(f"Total scans: {result.get('total_scans', 0)}")
    print(f"Total errors: {result.get('total_errors', 0)}")
    print(f"PPS change: {result.get('pps_change', 0):.1f}")
    print(f"Memory growth: {result.get('mem_growth', 0):+.1f} MB")
    
    print("\nISSUES:")
    if result.get("issues"):
        for issue in result["issues"]:
            print(f"  ⚠ {issue}")
    else:
        print("  ✓ None detected")
    
    print(f"\nStatus: {result.get('status', 'UNKNOWN')}")
    print(f"Results saved to: {output_file}")
    
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="API Soak Test")
    parser.add_argument("-d", "--duration", type=int, default=30)
    parser.add_argument("-i", "--interval", type=int, default=5)
    parser.add_argument("-a", "--api", type=str, default=API_BASE)
    parser.add_argument("-o", "--output", type=str, default=OUTPUT_FILE)
    
    args = parser.parse_args()
    
    asyncio.run(main(
        args.duration,
        args.interval,
        args.api,
        args.output
    ))