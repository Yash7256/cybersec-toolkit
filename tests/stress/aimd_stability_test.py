#!/usr/bin/env python3
"""
AIMD Concurrency Stability Test.
Tests async port scanner at different concurrency levels.
"""
import asyncio
import argparse
import time
import sys
from typing import Optional

import httpx


API_BASE = "http://localhost:8000/api"
DEFAULT_TARGET = "scanme.nmap.org"
PORT_RANGE = "top1000"  # Common ports for stability test
REQUEST_TIMEOUT = 120.0


class AIMDStabilityTest:
    """AIMD concurrency stability evaluator."""
    
    def __init__(self, target: str, api_base: str = API_BASE):
        self.target = target
        self.api_base = api_base.rstrip("/")
        self.results: list[dict] = []
        
    async def check_api(self, client: httpx.AsyncClient) -> bool:
        """Check API availability."""
        try:
            r = await client.get(f"{self.api_base}/scans/health", timeout=5.0)
            return r.status_code == 200
        except Exception:
            return False
    
    async def submit_scan(
        self, 
        client: httpx.AsyncClient,
        timeout: float = 5.0
    ) -> Optional[str]:
        """Submit scan with specified timeout."""
        payload = {
            "target": self.target,
            "port_range": PORT_RANGE,
            "scan_type": "connect",
            "timeout": timeout,
            "rate_preset": "aggressive"
        }
        
        try:
            r = await client.post(
                f"{self.api_base}/scans/",
                json=payload,
                timeout=30.0
            )
            if r.status_code != 200:
                return None
            data = r.json()
            return data.get("id") or data.get("scan_id")
        except Exception:
            return None
    
    async def wait_for_completion(
        self, 
        client: httpx.AsyncClient,
        scan_id: str,
        max_wait: int = 120
    ) -> bool:
        """Poll scan completion."""
        for _ in range(max_wait):
            try:
                r = await client.get(
                    f"{self.api_base}/scans/{scan_id}/status",
                    timeout=10.0
                )
                if r.status_code != 200:
                    await asyncio.sleep(1)
                    continue
                data = r.json()
                status = data.get("status", "unknown")
                if status == "completed":
                    return True
                elif status == "failed":
                    return False
                await asyncio.sleep(1)
            except Exception:
                await asyncio.sleep(1)
        return False
    
    async def get_results(self, client: httpx.AsyncClient, scan_id: str) -> Optional[dict]:
        """Fetch scan results with metrics."""
        try:
            r = await client.get(
                f"{self.api_base}/scans/{scan_id}",
                timeout=30.0
            )
            if r.status_code != 200:
                return None
            return r.json()
        except Exception:
            return None
    
    async def run_single_test(
        self,
        client: httpx.AsyncClient,
        concurrency: int
    ) -> Optional[dict]:
        """Run single concurrency test."""
        
        print(f"Testing concurrency={concurrency}...", end=" ", flush=True)
        
        # Submit scan
        start = time.perf_counter()
        scan_id = await self.submit_scan(client, timeout=10.0)
        
        if not scan_id:
            print("SUBMIT FAILED")
            return None
        
        # Wait for completion
        done = await self.wait_for_completion(client, scan_id, max_wait=120)
        
        if not done:
            print("TIMEOUT")
            return None
        
        # Get results
        results = await self.get_results(client, scan_id)
        
        if not results:
            print("NO RESULTS")
            return None
        
        end = time.perf_counter()
        duration = end - start
        
        # Extract metrics
        metrics = results.get("metrics")
        
        if not metrics:
            print("NO METRICS")
            return None
        
        computed = metrics.get("computed", {})
        system = metrics.get("system", {})
        
        pps_api = computed.get("ports_per_second", 0)
        error_rate = computed.get("error_rate", 0)
        cpu = system.get("cpu_percent", 0)
        memory = system.get("memory_mb", 0)
        
        return {
            "concurrency": concurrency,
            "duration": duration,
            "ports_per_second": pps_api,
            "error_rate": error_rate,
            "cpu_percent": cpu,
            "memory_mb": memory
        }
    
    async def run_stability_test(
        self,
        concurrency_levels: list[int]
    ) -> list[dict]:
        """Run stability test across concurrency levels."""
        
        print("=" * 70)
        print(f"AIMD CONCURRENCY STABILITY TEST")
        print(f"Target: {self.target}")
        print(f"Ports: {PORT_RANGE}")
        print("=" * 70)
        
        async with httpx.AsyncClient() as client:
            # Check API
            if not await self.check_api(client):
                raise RuntimeError("API not available")
            print("API OK\n")
            
            results = []
            prev_result = None
            
            for level in concurrency_levels:
                result = await self.run_single_test(client, level)
                
                if result:
                    results.append(result)
                    
                    # Detect instability
                    if prev_result:
                        error_delta = result["error_rate"] - prev_result["error_rate"]
                        pps_delta = prev_result["ports_per_second"] - result["ports_per_second"]
                        
                        if error_delta > 10:
                            print(f"  ⚠ HIGH ERROR SPIKE: +{error_delta:.1f}%")
                        if pps_delta > 10:
                            print(f"  ⚠ LATENCY SPIKE: -{pps_delta:.1f} pps")
                    
                    prev_result = result
                else:
                    print(f"  ✗ FAILED")
                
                # Delay between tests
                await asyncio.sleep(2)
        
        return results


def print_table(results: list[dict]):
    """Print results in table format."""
    
    header = f"{'Concurrency':>12} | {'Time(s)':>8} | {'Ports/sec':>10} | {'Error%':>8} | {'CPU%':>7} | {'Memory':>9}"
    separator = "-" * len(header)
    
    print("\n" + "=" * 70)
    print("RESULTS TABLE")
    print("=" * 70)
    print(header)
    print(separator)
    
    for r in results:
        print(f"{r['concurrency']:>12} | {r['duration']:>8.2f} | {r['ports_per_second']:>10.2f} | {r['error_rate']:>8.2f} | {r['cpu_percent']:>7.2f} | {r['memory_mb']:>9.2f}")
    
    print(separator)
    
    # Summary
    if results:
        avg_pps = sum(r["ports_per_second"] for r in results) / len(results)
        avg_errors = sum(r["error_rate"] for r in results) / len(results)
        avg_memory = sum(r["memory_mb"] for r in results) / len(results)
        
        print(f"{'AVERAGES':>12} | {'':>8} | {avg_pps:>10.2f} | {avg_errors:>8.2f} | {'':>7} | {avg_memory:>9.2f}")
    
    print("=" * 70)
    
    # Detect issues
    print("\nSTABILITY ANALYSIS:")
    
    if len(results) >= 2:
        # Check for error rate increase
        error_trend = results[-1]["error_rate"] - results[0]["error_rate"]
        if abs(error_trend) > 20:
            print(f"  ⚠ ERROR RATE TREND: {error_trend:+.1f}%")
        else:
            print(f"  ✓ ERROR RATE STABLE: {error_trend:+.1f}%")
        
        # Check for pps degradation
        pps_trend = results[0]["ports_per_second"] - results[-1]["ports_per_second"]
        if pps_trend > 20:
            print(f"  ⚠ THROUGHPUT DEGRADATION: -{pps_trend:.1f} pps")
        else:
            print(f"  ✓ THROUGHPUT STABLE")
        
        # Check memory growth
        mem_growth = results[-1]["memory_mb"] - results[0]["memory_mb"]
        if mem_growth > 100:
            print(f"  ⚠ MEMORY LEAK: +{mem_growth:.1f} MB")
        else:
            print(f"  ✓ MEMORY OK: +{mem_growth:+.1f} MB")


async def main(target: str = DEFAULT_TARGET, api_base: str = API_BASE):
    """Main entry point."""
    
    test = AIMDStabilityTest(target, api_base)
    
    results = await test.run_stability_test([50, 100, 200, 300, 400, 500])
    
    print_table(results)
    
    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AIMD Concurrency Stability Test")
    parser.add_argument("-t", "--target", type=str, default=DEFAULT_TARGET)
    parser.add_argument("-a", "--api", type=str, default=API_BASE)
    
    args = parser.parse_args()
    
    asyncio.run(main(args.target, args.api))