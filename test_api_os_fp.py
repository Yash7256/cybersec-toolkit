#!/usr/bin/env python3
"""
Test OS fingerprinting API directly
"""
import asyncio
import sys
import os

# Add current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cybersec.core.scanner.engine import AsyncPortScanner
from cybersec.core.scanner.analysis.os_fingerprint import OSFingerprinter

async def test_os_fingerprint():
    print("=== Testing OS Fingerprinting API Flow ===")
    
    # Step 1: Scan the target
    print("1. Scanning scanme.nmap.org...")
    scanner = AsyncPortScanner(timeout=5.0)
    report = await scanner.scan('scanme.nmap.org', '22,80,443')
    
    print(f"   Open ports: {len(report.open_ports)}")
    for port in report.open_ports:
        print(f"   Port {port.port}: {port.state}")
        if port.service:
            print(f"     Service: {port.service.service_name}")
            print(f"     Banner: {port.service.banner_snippet}")
    
    # Step 2: Collect banners
    banners = [
        r.service.banner_snippet
        for r in report.open_ports
        if r.service and r.service.banner_snippet
    ]
    
    print(f"2. Collected banners: {banners}")
    
    # Step 3: OS fingerprinting
    print("3. Running OS fingerprinting...")
    fingerprinter = OSFingerprinter()
    
    # Try active fingerprinting first
    try:
        fp = fingerprinter.fingerprint_active('scanme.nmap.org', [r.port for r in report.open_ports])
        print(f"   Active fingerprinting successful!")
    except Exception as e:
        print(f"   Active fingerprinting failed: {e}")
        print("   Falling back to banner analysis...")
        fp = fingerprinter.fingerprint(banners, [r.port for r in report.open_ports])
    
    print(f"4. Results:")
    print(f"   OS: {fp.os_name}")
    print(f"   Vendor: {fp.vendor}")
    print(f"   Version: {fp.version}")
    print(f"   Confidence: {fp.confidence}%")
    print(f"   Method: {fp.method}")
    print(f"   Family: {fp.os_family}")
    print(f"   Signals used: {fp.signals_used}")
    
    # Step 4: Format API response
    result_data = {
        "target": "scanme.nmap.org",
        "ip": report.ip,
        "os_name": fp.os_name,
        "confidence": fp.confidence,
        "confidence_pct": round(fp.confidence * 100, 1),
        "method": fp.method,
        "vendor": fp.vendor,
        "os_family": fp.os_family,
        "version": fp.version,
        "ambiguous": fp.ambiguous,
        "signals_used": fp.signals_used,
        "hop_count": fp.hop_count,
        "tech_details": {
            "ttl": fp.tech_details.ttl,
            "window_size": fp.tech_details.window_size,
            "df_flag": fp.tech_details.df_flag,
            "tcp_options": fp.tech_details.tcp_options
        },
        "open_ports": [r.port for r in report.open_ports],
        "open_ports_scanned": [r.port for r in report.open_ports],
        "scan_duration": report.scan_duration,
    }
    
    print(f"5. API Response Format:")
    import json
    print(json.dumps(result_data, indent=2))

if __name__ == "__main__":
    asyncio.run(test_os_fingerprint())
