#!/usr/bin/env python3
"""Test script for port scanner."""

import asyncio
import sys
import os

# Add the project root to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cybersec.core.tools.port_scanner import scan_ports, scan_port_range


async def test_common_ports():
    """Test scanning common ports on a target."""
    print("=" * 60)
    print("Testing Port Scanner - Common Ports")
    print("=" * 60)
    
    target = "example.com"
    print(f"\nScanning common ports on {target}...")
    
    result = await scan_ports(target)
    
    if result.error:
        print(f"Error: {result.error}")
        return
    
    print(f"\nScan Results for {target}:")
    print(f"Total ports scanned: {result.total_scanned}")
    print(f"Open ports found: {result.open_ports_count}")
    print(f"Scan duration: {result.scan_duration_seconds:.2f} seconds")
    
    if result.open_ports:
        print(f"\nOpen Ports Details:")
        print("-" * 60)
        for port in result.open_ports:
            print(f"Port {port.port_number:5d} | {port.service:15s} | {port.status}")
    else:
        print("\nNo open ports found on common ports.")


async def test_port_range():
    """Test scanning a range of ports."""
    print("\n" + "=" * 60)
    print("Testing Port Scanner - Port Range")
    print("=" * 60)
    
    target = "example.com"
    start_port = 80
    end_port = 85
    print(f"\nScanning ports {start_port}-{end_port} on {target}...")
    
    result = await scan_port_range(target, start_port, end_port)
    
    if result.error:
        print(f"Error: {result.error}")
        return
    
    print(f"\nScan Results for {target}:")
    print(f"Total ports scanned: {result.total_scanned}")
    print(f"Open ports found: {result.open_ports_count}")
    print(f"Scan duration: {result.scan_duration_seconds:.2f} seconds")
    
    if result.open_ports:
        print(f"\nOpen Ports Details:")
        print("-" * 60)
        for port in result.open_ports:
            print(f"Port {port.port_number:5d} | {port.service:15s} | {port.status}")
    else:
        print(f"\nNo open ports found in range {start_port}-{end_port}.")


async def test_custom_ports():
    """Test scanning custom specific ports."""
    print("\n" + "=" * 60)
    print("Testing Port Scanner - Custom Ports")
    print("=" * 60)
    
    target = "example.com"
    custom_ports = [80, 443, 22, 53]
    print(f"\nScanning custom ports {custom_ports} on {target}...")
    
    result = await scan_ports(target, ports=custom_ports)
    
    if result.error:
        print(f"Error: {result.error}")
        return
    
    print(f"\nScan Results for {target}:")
    print(f"Total ports scanned: {result.total_scanned}")
    print(f"Open ports found: {result.open_ports_count}")
    print(f"Scan duration: {result.scan_duration_seconds:.2f} seconds")
    
    if result.open_ports:
        print(f"\nOpen Ports Details:")
        print("-" * 60)
        for port in result.open_ports:
            print(f"Port {port.port_number:5d} | {port.service:15s} | {port.status}")
    else:
        print(f"\nNo open ports found in custom list {custom_ports}.")


async def main():
    """Run all tests."""
    try:
        await test_common_ports()
        await test_port_range()
        await test_custom_ports()
        print("\n" + "=" * 60)
        print("All tests completed!")
        print("=" * 60)
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user.")
    except Exception as e:
        print(f"\n\nTest failed with error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())
