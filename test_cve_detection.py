#!/usr/bin/env python3
"""
Test script for CVE detection functionality.
"""
import asyncio
from cybersec.core.tools.cve_detect import detect_cves_for_version, parse_version_string


async def test_cve_detection():
    """Test CVE detection with known vulnerable versions."""
    
    # Test cases with known CVEs
    test_cases = [
        "Apache/2.4.49",  # CVE-2021-41773 (Critical)
        "nginx/1.18.0",   # Various CVEs
        "OpenSSH_8.2p1",  # Various CVEs
    ]
    
    print("Testing CVE Detection")
    print("=" * 60)
    
    for version_str in test_cases:
        print(f"\nTesting: {version_str}")
        print("-" * 40)
        
        # Test parsing
        parsed = parse_version_string(version_str)
        if parsed:
            service, version = parsed
            print(f"Parsed: service='{service}', version='{version}'")
        else:
            print("Failed to parse version string")
            continue
        
        # Test CVE detection
        try:
            result = await detect_cves_for_version(version_str)
            if result:
                print(f"CVEs found: {result.total_count}")
                print(f"  Critical: {result.critical_count}")
                print(f"  High: {result.critical_count}")
                print(f"  Medium: {result.medium_count}")
                print(f"  Low: {result.low_count}")
                
                if result.cves:
                    print("\nTop CVEs:")
                    for cve in result.cves[:3]:
                        print(f"  - {cve.cve_id} ({cve.severity}) - CVSS: {cve.cvss_score}")
                        print(f"    {cve.description[:100]}...")
            else:
                print("No CVE result returned")
        except Exception as e:
            print(f"Error during CVE detection: {e}")
    
    print("\n" + "=" * 60)
    print("Test complete")


if __name__ == "__main__":
    asyncio.run(test_cve_detection())
