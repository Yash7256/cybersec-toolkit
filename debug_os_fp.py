#!/usr/bin/env python3
"""
Debug OS fingerprinting API issue
"""
import asyncio
import sys
import os

# Add current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cybersec.core.scanner.engine import AsyncPortScanner
from cybersec.core.scanner.analysis.os_fingerprint import OSFingerprinter

async def debug_os_fingerprint():
    print("=== Debug OS Fingerprinting ===")
    
    # Scan the target
    scanner = AsyncPortScanner(timeout=5.0)
    report = await scanner.scan('scanme.nmap.org', '22,80,443')
    
    print(f"Open ports: {len(report.open_ports)}")
    for port in report.open_ports:
        print(f"Port {port.port}: {port.state}")
        if port.service:
            print(f"  Service: {port.service.service_name}")
            print(f"  Banner: {repr(port.service.banner_snippet)}")
    
    # Collect banners exactly like the API
    banners = [
        r.service.banner_snippet
        for r in report.open_ports
        if r.service and r.service.banner_snippet
    ]
    
    print(f"\nCollected banners: {repr(banners)}")
    
    # Test fingerprinting
    fingerprinter = OSFingerprinter()
    
    print("\n=== Testing with collected banners ===")
    if banners:
        fp = fingerprinter.fingerprint(banners, [r.port for r in report.open_ports])
        print(f"OS: {fp.os_name}")
        print(f"Vendor: {fp.vendor}")
        print(f"Confidence: {fp.confidence}%")
        print(f"Method: {fp.method}")
    else:
        print("No banners found!")
    
    print("\n=== Testing with known good banner ===")
    test_banner = 'SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13'
    fp = fingerprinter.fingerprint([test_banner], [22])
    print(f"OS: {fp.os_name}")
    print(f"Vendor: {fp.vendor}")
    print(f"Confidence: {fp.confidence}%")
    print(f"Method: {fp.method}")

if __name__ == "__main__":
    asyncio.run(debug_os_fingerprint())
