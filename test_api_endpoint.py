#!/usr/bin/env python3
"""Test script for port scanner API endpoint."""

import asyncio
import sys
import os

# Add the project root to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cybersec.core.tools.port_scanner import scan_ports, scan_port_range


async def test_api_endpoint_logic():
    """Test the logic that will be used in the API endpoint."""
    print("=" * 60)
    print("Testing API Endpoint Logic")
    print("=" * 60)
    
    # Test 1: Common ports (default)
    print("\n1. Testing common ports scan (default)...")
    result = await scan_ports("example.com")
    print(f"   Total scanned: {result.total_scanned}")
    print(f"   Open ports: {result.open_ports_count}")
    print(f"   Duration: {result.scan_duration_seconds:.2f}s")
    
    # Test 2: Custom ports
    print("\n2. Testing custom ports scan...")
    result = await scan_ports("example.com", ports=[80, 443, 22])
    print(f"   Total scanned: {result.total_scanned}")
    print(f"   Open ports: {result.open_ports_count}")
    print(f"   Duration: {result.scan_duration_seconds:.2f}s")
    
    # Test 3: Port range
    print("\n3. Testing port range scan...")
    result = await scan_port_range("example.com", 80, 85)
    print(f"   Total scanned: {result.total_scanned}")
    print(f"   Open ports: {result.open_ports_count}")
    print(f"   Duration: {result.scan_duration_seconds:.2f}s")
    
    # Test 4: Custom timeout and concurrency
    print("\n4. Testing custom timeout and concurrency...")
    result = await scan_ports("example.com", timeout=1.0, max_concurrent=50)
    print(f"   Total scanned: {result.total_scanned}")
    print(f"   Open ports: {result.open_ports_count}")
    print(f"   Duration: {result.scan_duration_seconds:.2f}s")
    
    print("\n" + "=" * 60)
    print("API endpoint logic tests completed successfully!")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(test_api_endpoint_logic())
