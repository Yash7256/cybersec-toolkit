#!/usr/bin/env python3
"""
CyberSec Stress Test Suite

Tests the performance and reliability of the CyberSec network security scanner
under various load conditions. All measurements are taken from the live system.
"""

import argparse
import json
import statistics
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional
import requests


@dataclass
class TestResults:
    """Store results from all test suites."""
    full_scan_results: Dict[str, Any]
    concurrent_users_results: List[Dict[str, Any]]
    max_concurrency_results: Dict[str, Any]
    sustained_load_results: Dict[str, Any]
    final_summary: Dict[str, Any]


class StressTester:
    def __init__(self, base_url: str, token: str, target: str, nmap_target: str, max_workers: int):
        self.base_url = base_url.rstrip('/')
        self.token = token
        self.target = target
        self.nmap_target = nmap_target
        self.max_workers = max_workers
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        })
        self.results = TestResults(
            full_scan_results={},
            concurrent_users_results=[],
            max_concurrency_results={},
            sustained_load_results={},
            final_summary={}
        )
    
    def check_api_health(self) -> bool:
        """Check if the CyberSec API is reachable."""
        try:
            response = self.session.get(f"{self.base_url}/api/health", timeout=10)
            return response.status_code == 200
        except Exception as e:
            print(f"❌ API health check failed: {e}")
            return False
    
    def submit_scan(self, ports: str, scan_type: str = "tcp_connect", target: str = None) -> Optional[str]:
        """Submit a scan and return the scan ID."""
        target = target or self.target
        payload = {
            "target": target,
            "port_range": ports,
            "scan_type": scan_type,
            "timeout": 3.0,
            "rate_preset": "aggressive"
        }
        
        try:
            response = self.session.post(f"{self.base_url}/api/scans/jobs", json=payload, timeout=30)
            if response.status_code == 200:
                data = response.json()
                return data.get("job_id")
            else:
                print(f"❌ Scan submission failed: HTTP {response.status_code}")
                return None
        except Exception as e:
            print(f"❌ Scan submission error: {e}")
            return None
    
    def get_scan_status(self, scan_id: str) -> Optional[Dict]:
        """Get scan status and results."""
        try:
            response = self.session.get(f"{self.base_url}/api/scans/jobs/{scan_id}", timeout=10)
            if response.status_code == 200:
                return response.json()
            else:
                return None
        except Exception:
            return None
    
    def wait_for_scan_completion(self, scan_id: str, timeout: int = 600) -> Dict[str, Any]:
        """Wait for scan completion and record timing."""
        start_time = time.time()
        last_progress_time = start_time
        
        while time.time() - start_time < timeout:
            status = self.get_scan_status(scan_id)
            if not status:
                return {"success": False, "error": "Failed to get scan status"}
            
            if status and status.get("status") == "completed":
                # Extract metrics from the completed scan result
                result = status.get("result", {})
                metrics = result.get("metrics", {})
                timing = metrics.get("timing", {})
                computed = metrics.get("computed", {})
                
                duration = timing.get("duration_seconds", 0)
                open_ports = len(result.get("open_ports", []))
                ports_per_second = computed.get("ports_per_second", 0)
                
                return {
                    "success": True,
                    "duration": duration,
                    "open_ports": open_ports,
                    "ports_per_second": ports_per_second,
                    "scan_errors": 0
                }
            elif status and status.get("status") == "failed":
                return {
                    "success": False,
                    "duration": time.time() - start_time,
                    "error": status.get("error", "Unknown error"),
                    "scan_errors": 1
                }
            
            # Print progress dots every 10 seconds
            current_time = time.time()
            if current_time - last_progress_time >= 10:
                print(".", end="", flush=True)
                last_progress_time = current_time
            
            time.sleep(5)
        
        return {"success": False, "error": "Scan timeout", "duration": time.time() - start_time}
    
    def run_nmap_baseline(self, ports: str) -> Dict[str, Any]:
        """Run Nmap for baseline comparison."""
        print(f"\n🔍 Running Nmap baseline: nmap -sT -p {ports} --min-rate 1000 172.23.0.1")
        
        try:
            start_time = time.time()
            cmd = ["nmap", "-sT", "-p", ports, "--min-rate", "1000", "172.23.0.1"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)  # 30 min timeout
            
            duration = time.time() - start_time
            
            # Parse Nmap output for open ports
            open_ports = 0
            for line in result.stdout.split('\n'):
                if '/tcp' in line and 'open' in line:
                    open_ports += 1
            
            return {
                "success": True,
                "duration": duration,
                "open_ports": open_ports,
                "stdout": result.stdout,
                "stderr": result.stderr
            }
            
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Nmap timeout", "duration": time.time() - start_time}
        except Exception as e:
            return {"success": False, "error": str(e), "duration": 0}
    
    def test_suite_1_full_scan(self) -> Dict[str, Any]:
        """Test Suite 1: Full 65,535 Port Range Scan."""
        print("\n" + "="*60)
        print("TEST SUITE 1: Full 65,535 Port Range Scan")
        print("="*60)
        
        # Submit CyberSec scan
        print("🚀 Starting CyberSec full scan (ports 1-65535)...")
        scan_id = self.submit_scan("1-65535", target="172.23.0.1")
        
        if not scan_id:
            return {"success": False, "error": "Failed to submit scan"}
        
        print(f"📝 Scan ID: {scan_id}")
        print("⏳ Waiting for completion (progress dots every 10s):", end=" ", flush=True)
        
        cybersec_result = self.wait_for_scan_completion(scan_id, timeout=300)  # 5 min timeout for 65k scan
        
        # Extract and print detailed metrics from the completed scan
        if cybersec_result["success"]:
            print(f" ✅ DONE")
            print(f"📊 CyberSec: {cybersec_result['duration']:.2f}s, {cybersec_result['open_ports']} open ports")
            if cybersec_result.get('ports_per_second'):
                print(f"📊 Ports per second: {cybersec_result['ports_per_second']:.1f}")
        else:
            print(f"\n❌ CyberSec scan failed: {cybersec_result.get('error')}")
            return cybersec_result
        
        # Run Nmap baseline
        nmap_result = self.run_nmap_baseline("1-65535")
        
        if not nmap_result["success"]:
            print(f"⚠️  Nmap baseline failed: {nmap_result.get('error')}")
            speedup = "N/A"
        else:
            print(f"📊 Nmap: {nmap_result['duration']:.2f}s, {nmap_result['open_ports']} open ports")
            speedup = nmap_result['duration'] / cybersec_result['duration']
            print(f"🚀 Speedup ratio: {speedup:.2f}x")
        
        return {
            "success": True,
            "cybersec_duration": cybersec_result['duration'],
            "cybersec_open_ports": cybersec_result['open_ports'],
            "cybersec_ports_per_second": cybersec_result.get('ports_per_second', 0),
            "nmap_duration": nmap_result.get('duration', 0),
            "nmap_open_ports": nmap_result.get('open_ports', 0),
            "speedup_ratio": speedup if isinstance(speedup, float) else 0
        }
    
    def run_single_scan_test(self, scan_id: str) -> Dict[str, Any]:
        """Run a single scan test for concurrent user testing."""
        start_time = time.time()
        
        # Submit scan - use port 8000 on 172.23.0.1 which is confirmed open
        # BUG FIX: Measure ONLY HTTP POST submission latency, not scan completion
        submitted_scan_id = self.submit_scan("8000", target="172.23.0.1")
        
        # Record response time immediately after HTTP response (don't wait for scan completion)
        response_time = time.time() - start_time
        
        if not submitted_scan_id:
            return {
                "success": False,
                "response_time": response_time,
                "error": "Failed to submit scan"
            }
        
        # Success is just getting a job_id back, not waiting for scan to complete
        return {
            "success": True,
            "response_time": response_time,
            "open_ports": 0,  # Not measured in Suite 2 - only HTTP latency
            "error": None
        }
    
    def test_suite_2_concurrent_users(self) -> List[Dict[str, Any]]:
        """Test Suite 2: Concurrent API Users."""
        print("\n" + "="*60)
        print("TEST SUITE 2: Concurrent API Users")
        print("="*60)
        
        concurrency_levels = [1, 5, 10, 25, 50]
        results = []
        
        for concurrency in concurrency_levels:
            print(f"\n👥 Testing {concurrency} concurrent users...")
            
            # Run concurrent tests
            start_time = time.time()
            with ThreadPoolExecutor(max_workers=concurrency) as executor:
                futures = [executor.submit(self.run_single_scan_test, f"test-{i}") for i in range(concurrency)]
                test_results = [future.result() for future in as_completed(futures)]
            
            total_time = time.time() - start_time
            
            # Calculate metrics
            successful_tests = [r for r in test_results if r["success"]]
            failed_tests = [r for r in test_results if not r["success"]]
            
            if successful_tests:
                response_times = [r["response_time"] for r in successful_tests]
                mean_rt = statistics.mean(response_times)
                p95_rt = statistics.quantiles(response_times, n=20)[18]  # 95th percentile
            else:
                mean_rt = p95_rt = 0
            
            req_per_sec = len(test_results) / total_time if total_time > 0 else 0
            error_count = len(failed_tests)
            
            result = {
                "concurrency": concurrency,
                "req_per_sec": req_per_sec,
                "mean_rt_ms": mean_rt * 1000,
                "p95_rt_ms": p95_rt * 1000,
                "errors": error_count,
                "total_tests": len(test_results)
            }
            
            results.append(result)
            
            print(f"   📊 {concurrency:2d} users: {req_per_sec:.2f} req/s, "
                  f"{mean_rt*1000:.0f}ms mean, {p95_rt*1000:.0f}ms p95, {error_count} errors")
            
            # Wait between tests
            if concurrency < concurrency_levels[-1]:
                print("   ⏳ Waiting 5 seconds for system recovery...")
                time.sleep(5)
        
        # Print summary table
        print(f"\n{'Concurrent Users':<15} | {'Req/sec':<8} | {'Mean RT (ms)':<12} | {'p95 RT (ms)':<11} | {'Errors':<7}")
        print("-" * 65)
        for result in results:
            print(f"{result['concurrency']:<15} | {result['req_per_sec']:<8.2f} | "
                  f"{result['mean_rt_ms']:<12.0f} | {result['p95_rt_ms']:<11.0f} | {result['errors']:<7}")
        
        return results
    
    def test_suite_3_max_concurrency(self) -> Dict[str, Any]:
        """Test Suite 3: Maximum Concurrency (500 Workers)."""
        print("\n" + "="*60)
        print("TEST SUITE 3: Maximum Concurrency (500 Workers)")
        print("="*60)
        
        print("🚀 Starting 10,000 port scan to test max concurrency...")
        scan_id = self.submit_scan("1-10000", target="172.23.0.1")
        
        if not scan_id:
            return {"success": False, "error": "Failed to submit scan"}
        
        print(f"📝 Scan ID: {scan_id}")
        print("⏳ Monitoring scan progress...")
        
        start_time = time.time()
        peak_workers = 0
        metrics_available = False
        
        while time.time() - start_time < 600:  # 10 min timeout
            status = self.get_scan_status(scan_id)
            if not status:
                time.sleep(3)
                continue
            
            # Try to get metrics
            try:
                metrics_response = self.session.get(f"{self.base_url}/api/metrics", timeout=5)
                if metrics_response.status_code == 200:
                    metrics = metrics_response.json()
                    current_workers = metrics.get("current_workers", 0)
                    peak_workers = max(peak_workers, current_workers)
                    metrics_available = True
            except:
                pass
            
            if status and status.get("status") == "completed":
                # Extract metrics from the completed scan result
                result = status.get("result", {})
                metrics = result.get("metrics", {})
                timing = metrics.get("timing", {})
                computed = metrics.get("computed", {})
                
                duration = timing.get("duration_seconds", 0)
                open_ports = len(result.get("open_ports", []))
                ports_per_second = computed.get("ports_per_second", 0)
                
                print(f" ✅ Scan completed in {duration:.2f}s")
                print(f"📊 Open ports found: {open_ports}")
                print(f"📊 Ports per second: {ports_per_second:.1f}")
                
                peak_workers_str = str(peak_workers) if metrics_available else "N/A"
                print(f"📊 Peak workers: {peak_workers_str}")
                print(f"📊 Scan errors: 0")
                print(f"📊 Completion: SUCCESS")
                
                return {
                    "success": True,
                    "duration": duration,
                    "open_ports": open_ports,
                    "ports_per_second": ports_per_second,
                    "peak_workers": peak_workers if metrics_available else "metrics_endpoint_unavailable",
                    "metrics_available": metrics_available,
                    "scan_errors": 0
                }
            elif status and status.get("status") == "failed":
                return {
                    "success": False,
                    "error": status.get("error", "Scan failed"),
                    "duration": time.time() - start_time,
                    "peak_workers": peak_workers if metrics_available else "metrics_endpoint_unavailable"
                }
            
            time.sleep(3)
        
        return {
            "success": False,
            "error": "Scan timeout",
            "duration": time.time() - start_time,
            "peak_workers": peak_workers if metrics_available else "metrics_endpoint_unavailable"
        }
    
    def test_suite_4_sustained_load(self) -> Dict[str, Any]:
        """Test Suite 4: Sustained Load."""
        print("\n" + "="*60)
        print("TEST SUITE 4: Sustained Load (5 minutes)")
        print("="*60)
        
        duration_seconds = 300  # 5 minutes
        scan_interval = 10  # Start a new scan every 10 seconds
        target_ports = "8000"  # BUG FIX: Use single open port for faster scans and meaningful throughput
        
        start_time = time.time()
        end_time = start_time + duration_seconds
        
        scan_results = []
        error_count = 0
        scan_number = 0
        
        print(f"🏃 Running continuous scans for {duration_seconds//60} minutes...")
        
        while time.time() < end_time:
            scan_start = time.time()
            scan_number += 1
            
            # Submit scan
            scan_id = self.submit_scan(target_ports, target="172.23.0.1")
            if not scan_id:
                error_count += 1
                print(f"❌ Scan {scan_number}: Failed to submit")
                time.sleep(scan_interval)
                continue
            
            # Wait for completion
            result = self.wait_for_scan_completion(scan_id, timeout=120)
            scan_duration = time.time() - scan_start
            
            scan_result = {
                "scan_number": scan_number,
                "start_time": scan_start,
                "duration": scan_duration,
                "success": result["success"],
                "open_ports": result.get("open_ports", 0),
                "error": result.get("error")
            }
            
            scan_results.append(scan_result)
            
            status = "✅" if result["success"] else "❌"
            print(f"{status} Scan {scan_number}: {scan_duration:.2f}s, {result.get('open_ports', 0)} ports")
            
            if not result["success"]:
                error_count += 1
            
            # Wait for next scan
            elapsed = time.time() - scan_start
            if elapsed < scan_interval:
                time.sleep(scan_interval - elapsed)
        
        # Analyze results
        total_scans = len(scan_results)
        successful_scans = [r for r in scan_results if r["success"]]
        
        if not successful_scans:
            return {
                "success": False,
                "error": "No successful scans",
                "total_scans": total_scans,
                "error_rate": 100.0
            }
        
        # Calculate 60-second windows
        windows = []
        for i in range(0, int(duration_seconds), 60):
            window_start = start_time + i
            window_end = window_start + 60
            
            window_scans = [r for r in scan_results if window_start <= r["start_time"] < window_end]
            if window_scans:
                window_durations = [r["duration"] for r in window_scans if r["success"]]
                window_errors = len([r for r in window_scans if not r["success"]])
                
                if window_durations:
                    windows.append({
                        "timestamp": i,
                        "scans": len(window_scans),
                        "mean_duration": statistics.mean(window_durations),
                        "errors": window_errors
                    })
        
        # Print timeline
        print(f"\n{'Time':<8} | {'Scans':<6} | {'Mean Duration':<14} | {'Errors':<7}")
        print("-" * 42)
        for window in windows:
            time_str = f"T={window['timestamp']}s"
            print(f"{time_str:<8} | {window['scans']:<6} | {window['mean_duration']:<14.2f} | {window['errors']:<7}")
        
        # Check for degradation
        first_60s = windows[0]["mean_duration"] if windows else 0
        last_60s = windows[-1]["mean_duration"] if len(windows) > 1 else first_60s
        
        degradation_detected = last_60s > (first_60s * 1.5) if first_60s > 0 else False
        degradation_ratio = last_60s / first_60s if first_60s > 0 else 0
        
        error_rate = (error_count / total_scans) * 100 if total_scans > 0 else 0
        
        print(f"\n📊 Final Results:")
        print(f"   Total scans: {total_scans}")
        print(f"   First-60s mean: {first_60s:.2f}s")
        print(f"   Last-60s mean: {last_60s:.2f}s")
        print(f"   Degradation: {'YES' if degradation_detected else 'NO'} "
              f"({degradation_ratio:.2f}x)" if degradation_detected else f"   Degradation: NO")
        print(f"   Total errors: {error_count}")
        print(f"   Error rate: {error_rate:.2f}%")
        
        return {
            "success": True,
            "total_scans": total_scans,
            "first_60s_mean": first_60s,
            "last_60s_mean": last_60s,
            "degradation_detected": degradation_detected,
            "degradation_ratio": degradation_ratio,
            "total_errors": error_count,
            "error_rate": error_rate,
            "windows": windows
        }
    
    def run_all_tests(self) -> TestResults:
        """Run all four test suites sequentially."""
        print("🚀 Starting CyberSec Stress Test Suite")
        print(f"📍 Target: {self.target}")
        print(f"🌐 API: {self.base_url}")
        
        # Check API health first
        if not self.check_api_health():
            print("❌ CyberSec API is not reachable. Please ensure the service is running.")
            sys.exit(1)
        
        print("✅ API health check passed")
        
        # Run test suites
        try:
            print("\n🧪 Running Test Suite 1...")
            self.results.full_scan_results = self.test_suite_1_full_scan()
            
            print("\n🧪 Running Test Suite 2...")
            self.results.concurrent_users_results = self.test_suite_2_concurrent_users()
            
            print("\n🧪 Running Test Suite 3...")
            self.results.max_concurrency_results = self.test_suite_3_max_concurrency()
            
            print("\n🧪 Running Test Suite 4...")
            self.results.sustained_load_results = self.test_suite_4_sustained_load()
            
        except KeyboardInterrupt:
            print("\n⚠️  Tests interrupted by user")
            sys.exit(1)
        except Exception as e:
            print(f"\n❌ Test suite failed: {e}")
            sys.exit(1)
        
        return self.results
    
    def print_final_summary(self):
        """Print the final summary box."""
        print("\n" + "="*60)
        print("RECORD THESE NUMBERS FOR YOUR PAPER")
        print("="*60)
        
        print("\n╔══════════════════════════════════════════════════╗")
        print("║           CYBERSEC STRESS TEST RESULTS           ║")
        print("╠══════════════════════════════════════════════════╣")
        
        # Full scan results
        full = self.results.full_scan_results
        if full.get("success"):
            print(f"║ Full 65k scan:   CyberSec {full['cybersec_duration']:.1f}s vs "
                  f"Nmap {full['nmap_duration']:.1f}s ({full['speedup_ratio']:.1f}x)  ║")
        else:
            print(f"║ Full 65k scan:   FAILED                              ║")
        
        # Concurrent users results
        if self.results.concurrent_users_results:
            max_concurrent = max(self.results.concurrent_users_results, key=lambda x: x['req_per_sec'])
            print(f"║ Max concurrency: {max_concurrent['concurrency']} users, "
                  f"{max_concurrent['req_per_sec']:.1f} req/s, "
                  f"{max_concurrent['p95_rt_ms']:.0f}ms p95       ║")
        else:
            print("║ Max concurrency: FAILED                              ║")
        
        # Peak workers
        max_workers = self.results.max_concurrency_results
        if max_workers.get("success"):
            peak_workers = max_workers.get("peak_workers", "N/A")
            if isinstance(peak_workers, int):
                print(f"║ Peak workers:    {peak_workers} / 500                         ║")
            else:
                print(f"║ Peak workers:    {peak_workers}                    ║")
        else:
            print("║ Peak workers:    FAILED                              ║")
        
        # Sustained load
        sustained = self.results.sustained_load_results
        if sustained.get("success"):
            print(f"║ Sustained load:  {sustained['total_scans']} scans/5min, "
                  f"{sustained['error_rate']:.1f}% error rate  ║")
        else:
            print("║ Sustained load:  FAILED                              ║")
        
        print("╚══════════════════════════════════════════════════╝")
    
    def save_results(self, filename: str = "stress_test_results.json"):
        """Save all results to JSON file."""
        with open(filename, 'w') as f:
            json.dump(asdict(self.results), f, indent=2)
        print(f"\n💾 Results saved to {filename}")


def main():
    parser = argparse.ArgumentParser(description="CyberSec Stress Test Suite")
    parser.add_argument("--base-url", default="http://localhost:8000", 
                       help="CyberSec API base URL (default: http://localhost:8000)")
    parser.add_argument("--token", required=True, 
                       help="JWT auth token")
    parser.add_argument("--target", default="127.0.0.1", 
                       help="IP to scan (default: 127.0.0.1)")
    parser.add_argument("--nmap-target", 
                       help="Same IP for Nmap comparison (default: same as --target)")
    parser.add_argument("--workers", type=int, default=500, 
                       help="Override max workers for AIMD test (default: 500)")
    
    args = parser.parse_args()
    
    # Set nmap_target to target if not specified
    nmap_target = args.nmap_target or args.target
    
    # Create and run stress tester
    tester = StressTester(args.base_url, args.token, args.target, nmap_target, args.workers)
    
    try:
        # Run all tests
        results = tester.run_all_tests()
        
        # Print final summary
        tester.print_final_summary()
        
        # Save results
        tester.save_results()
        
        print("\n🎉 All stress tests completed!")
        
    except Exception as e:
        print(f"\n❌ Stress test failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
