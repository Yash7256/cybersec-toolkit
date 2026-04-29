#!/usr/bin/env python3
"""
Full port range stress test via API (1-65535).
Async scanning with metrics measurement and validation.
"""
import asyncio
import argparse
import time
import sys
from typing import Optional

import httpx


API_BASE = "http://localhost:8000/api"
DEFAULT_TARGET = "scanme.nmap.org"
REQUEST_TIMEOUT = 300.0  # 5 minutes max for full scan


class FullPortScanner:
    """Full port range scanner with metrics."""
    
    def __init__(self, target: str, api_base: str = API_BASE):
        self.target = target
        self.api_base = api_base.rstrip("/")
        self.scan_id: Optional[str] = None
        self.results: dict = {}
        
    async def check_api_health(self, client: httpx.AsyncClient) -> bool:
        """Check if API is available."""
        try:
            r = await client.get(f"{self.api_base}/scans/health", timeout=5.0)
            return r.status_code == 200
        except Exception:
            return False
    
    async def submit_scan(
        self, 
        client: httpx.AsyncClient, 
        port_range: str = "1-65535",
        scan_type: str = "connect"
    ) -> Optional[str]:
        """Submit full port range scan."""
        payload = {
            "target": self.target,
            "port_range": port_range,
            "scan_type": scan_type,
            "timeout": 5.0,
            "rate_preset": "aggressive"
        }
        
        try:
            r = await client.post(
                f"{self.api_base}/scans/",
                json=payload,
                timeout=30.0
            )
            
            if r.status_code != 200:
                print(f"ERROR: Submit failed ({r.status_code}): {r.text}")
                return None
            
            data = r.json()
            self.scan_id = data.get("id") or data.get("scan_id")
            return self.scan_id
            
        except Exception as e:
            print(f"ERROR: Submit exception: {e}")
            return None
    
    async def wait_for_completion(
        self, 
        client: httpx.AsyncClient,
        max_wait: int = 300
    ) -> bool:
        """Poll scan status until completed."""
        if not self.scan_id:
            return False
        
        for attempt in range(max_wait):
            try:
                r = await client.get(
                    f"{self.api_base}/scans/{self.scan_id}/status",
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
                    error = data.get("error", "Unknown error")
                    print(f"SCAN FAILED: {error}")
                    return False
                
                # Still running
                await asyncio.sleep(1)
                
            except Exception as e:
                print(f"ERROR: Status check: {e}")
                await asyncio.sleep(1)
        
        print(f"WARNING: Scan did not complete within {max_wait}s")
        return False
    
    async def get_results(self, client: httpx.AsyncClient) -> Optional[dict]:
        """Fetch scan results with metrics."""
        if not self.scan_id:
            return None
        
        try:
            r = await client.get(
                f"{self.api_base}/scans/{self.scan_id}",
                timeout=30.0
            )
            
            if r.status_code != 200:
                print(f"ERROR: Get results failed ({r.status_code})")
                return None
            
            return r.json()
            
        except Exception as e:
            print(f"ERROR: Get results exception: {e}")
            return None
    
    async def run_full_scan(self) -> dict:
        """Execute full port range scan and collect metrics."""
        
        async with httpx.AsyncClient() as client:
            # Health check
            print(f"Checking API at {self.api_base}...")
            if not await self.check_api_health(client):
                raise RuntimeError("API not available")
            print("API OK")
            
            # Submit scan
            print(f"\nSubmitting full port scan for {self.target}...")
            wall_start = time.perf_counter()
            
            scan_id = await self.submit_scan(client, "1-65535")
            if not scan_id:
                raise RuntimeError("Failed to submit scan")
            
            print(f"Scan ID: {scan_id}")
            print("Waiting for completion...")
            
            # Wait for completion
            if not await self.wait_for_completion(client):
                raise RuntimeError("Scan did not complete")
            
            wall_end = time.perf_counter()
            wall_time = wall_end - wall_start
            
            # Get results
            print("Fetching results...")
            results = await self.get_results(client)
            
            if not results:
                raise RuntimeError("Failed to get results")
            
            return {
                "wall_time": wall_time,
                "results": results
            }


def validate_results(results: dict, expected_ports: int = 65535) -> dict:
    """Validate scan results and extract metrics."""
    
    scan_results = results.get("results", [])
    metrics = results.get("metrics")
    
    # Count ports
    found_ports = [r.get("port") for r in scan_results]
    open_count = len(found_ports)
    
    # Validate total scanned
    total_scanned = metrics.get("counters", {}).get("total_ports_scanned") if metrics else None
    
    validation = {
        "total_ports_scanned": total_scanned,
        "expected": expected_ports,
        "valid": total_scanned == expected_ports,
        "open_ports": open_count
    }
    
    # Extract metrics
    if metrics:
        computed = metrics.get("computed", {})
        system = metrics.get("system", {})
        
        extracted = {
            "ports_per_second_api": computed.get("ports_per_second", 0),
            "error_rate": computed.get("error_rate", 0),
            "connection_success_rate": computed.get("connection_success_rate", 0),
            "cpu_percent": system.get("cpu_percent", 0),
            "memory_mb": system.get("memory_mb", 0),
            "open_file_descriptors": system.get("open_file_descriptors", 0)
        }
    else:
        extracted = {
            "ports_per_second_api": 0,
            "error_rate": 0,
            "connection_success_rate": 0,
            "cpu_percent": 0,
            "memory_mb": 0,
            "open_file_descriptors": 0
        }
    
    return {
        "validation": validation,
        "metrics": extracted
    }


async def main(target: str = DEFAULT_TARGET, api_base: str = API_BASE):
    """Main entry point."""
    
    print("=" * 60)
    print("FULL PORT RANGE SCAN (1-65535)")
    print(f"Target: {target}")
    print(f"API: {api_base}")
    print("=" * 60)
    
    scanner = FullPortScanner(target, api_base)
    
    try:
        # Run scan
        output = await scanner.run_full_scan()
        
        wall_time = output["wall_time"]
        results = output["results"]
        
        # Validate and extract metrics
        validation_results = validate_results(results)
        
        validation = validation_results["validation"]
        metrics = validation_results["metrics"]
        
        # Calculate actual throughput
        ports_per_second_actual = validation["total_ports_scanned"] / wall_time if wall_time > 0 else 0
        
        # Print structured output
        print("\n" + "=" * 60)
        print("RESULTS")
        print("=" * 60)
        
        output_dict = {
            "scan_time": round(wall_time, 3),
            "total_ports_scanned": validation["total_ports_scanned"],
            "open_ports": validation["open_ports"],
            "ports_per_second_api": round(metrics["ports_per_second_api"], 4),
            "ports_per_second_actual": round(ports_per_second_actual, 4),
            "error_rate": round(metrics["error_rate"], 2),
            "connection_success_rate": round(metrics["connection_success_rate"], 2),
            "cpu_percent": round(metrics["cpu_percent"], 2),
            "memory_mb": round(metrics["memory_mb"], 2),
            "open_file_descriptors": metrics["open_file_descriptors"]
        }
        
        import json
        print(json.dumps(output_dict, indent=2))
        
        # Validation status
        print("\nVALIDATION:")
        if validation["valid"]:
            print("  ✓ total_ports_scanned == 65535")
        else:
            print(f"  ✗ total_ports_scanned = {validation['total_ports_scanned']} (expected 65535)")
        
        print("\n" + "=" * 60)
        
        return output_dict
        
    except Exception as e:
        print(f"\nERROR: {e}")
        sys.exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Full port range scan via API"
    )
    parser.add_argument(
        "-t", "--target",
        type=str,
        default=DEFAULT_TARGET,
        help="Target to scan"
    )
    parser.add_argument(
        "-a", "--api",
        type=str,
        default=API_BASE,
        help="API base URL"
    )
    
    args = parser.parse_args()
    
    asyncio.run(main(args.target, args.api))