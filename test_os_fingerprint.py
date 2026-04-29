#!/usr/bin/env python3
"""
Test script for OS fingerprinting functionality.
Run with regular user to test banner analysis, or with sudo for active fingerprinting.
"""
import sys
import os

# Add current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cybersec.core.scanner.analysis.os_fingerprint import OSFingerprinter

def test_banner_fingerprinting():
    print("=== Testing Banner-based OS Fingerprinting ===")
    fp = OSFingerprinter()
    
    # Test cases
    test_cases = [
        (['Ubuntu/4.15'], [80, 443], "Ubuntu banner"),
        (['Apache/2.4.41 (Debian)'], [80, 443], "Debian banner"),
        (['Microsoft-IIS/10.0'], [80, 443], "Windows IIS"),
        (['nginx/1.18.0'], [80, 443], "Generic nginx"),
    ]
    
    for banners, ports, description in test_cases:
        result = fp.fingerprint(banners, ports)
        print(f"\n{description}:")
        print(f"  OS: {result.os_name}")
        print(f"  Confidence: {result.confidence}%")
        print(f"  Method: {result.method}")
        print(f"  Vendor: {result.vendor}")
        print(f"  Version: {result.version}")

def test_active_fingerprinting():
    print("\n=== Testing Active OS Fingerprinting ===")
    print(f"Running as UID: {os.geteuid()}")
    
    if os.geteuid() != 0:
        print("Active fingerprinting requires root privileges. Try: sudo python3 test_os_fingerprint.py")
        return
    
    fp = OSFingerprinter()
    
    # Test with localhost (should be safe)
    try:
        result = fp.fingerprint_active('127.0.0.1', [22, 80, 443])
        print(f"\nActive fingerprinting result:")
        print(f"  OS: {result.os_name}")
        print(f"  Confidence: {result.confidence}%")
        print(f"  Method: {result.method}")
        print(f"  Vendor: {result.vendor}")
        print(f"  Family: {result.os_family}")
        print(f"  Signals used: {result.signals_used}")
        print(f"  Hop count: {result.hop_count}")
        print(f"  Ambiguous: {result.ambiguous}")
        
        if result.tech_details.ttl:
            print(f"  TTL: {result.tech_details.ttl}")
        if result.tech_details.window_size:
            print(f"  Window size: {result.tech_details.window_size}")
        if result.tech_details.tcp_options:
            print(f"  TCP options: {result.tech_details.tcp_options}")
            
    except Exception as e:
        print(f"Active fingerprinting error: {e}")

if __name__ == "__main__":
    test_banner_fingerprinting()
    test_active_fingerprinting()
