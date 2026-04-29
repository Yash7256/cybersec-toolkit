#!/usr/bin/env python3
"""
MITRE ATT&CK Mapping Validation Script

This script validates the ATT&CK mapping implementation by:
1. Printing the full ATTACK_TECHNIQUE_DB contents in a readable table
2. Testing CVE-to-ATT&CK mapping against real CVE descriptions
3. Testing scan enrichment with mock Docker lab data
4. Providing a final summary of validation results
"""

import sys
from pathlib import Path

# Add the cybersec package to Python path
sys.path.insert(0, str(Path(__file__).parent))

from cybersec.core.security.attack_mapping import (
    ATTACK_TECHNIQUE_DB,
    map_cve_to_attack,
    enrich_scan_with_attack
)
from cybersec.core.security.nvd_client import CVEResult
from cybersec.core.scanner.analysis.service_detect import ServiceDetectionResult


def print_attack_technique_db():
    """Print the full ATTACK_TECHNIQUE_DB contents in a readable table."""
    print("=" * 100)
    print("MITRE ATT&CK TECHNIQUE DATABASE CONTENTS")
    print("=" * 100)
    
    total_techniques = 0
    tactic_categories = set()
    
    # Service techniques
    print("\n🔧 SERVICE TECHNIQUES:")
    print("-" * 80)
    print(f"{'Service':<15} | {'Technique ID':<12} | {'Technique Name':<35} | {'Tactic':<20}")
    print("-" * 80)
    
    for service, techniques in ATTACK_TECHNIQUE_DB.get("service_techniques", {}).items():
        for tech in techniques:
            print(f"{service:<15} | {tech['id']:<12} | {tech['name'][:34]:<35} | {tech['tactic']:<20}")
            total_techniques += 1
            tactic_categories.add(tech['tactic'])
    
    # CVSS severity techniques
    print("\n🚨 CVSS SEVERITY TECHNIQUES:")
    print("-" * 80)
    print(f"{'Severity':<10} | {'Technique ID':<12} | {'Technique Name':<35} | {'Tactic':<20}")
    print("-" * 80)
    
    for severity, techniques in ATTACK_TECHNIQUE_DB.get("cvss_severity_techniques", {}).items():
        for tech in techniques:
            print(f"{severity:<10} | {tech['id']:<12} | {tech['name'][:34]:<35} | {tech['tactic']:<20}")
            total_techniques += 1
            tactic_categories.add(tech['tactic'])
    
    # Port techniques
    print("\n🔌 PORT TECHNIQUES:")
    print("-" * 80)
    print(f"{'Port':<6} | {'Technique ID':<12} | {'Technique Name':<35} | {'Tactic':<20}")
    print("-" * 80)
    
    for port, techniques in ATTACK_TECHNIQUE_DB.get("port_techniques", {}).items():
        for tech in techniques:
            print(f"{port:<6} | {tech['id']:<12} | {tech['name'][:34]:<35} | {tech['tactic']:<20}")
            total_techniques += 1
            tactic_categories.add(tech['tactic'])
    
    print(f"\n📊 DATABASE SUMMARY:")
    print(f"Total techniques in DB: {total_techniques}")
    print(f"Unique tactic categories: {sorted(list(tactic_categories))}")
    
    return total_techniques, sorted(list(tactic_categories))


def test_cve_mapping():
    """Test CVE-to-ATT&CK mapping with real CVE descriptions."""
    print("\n" + "=" * 100)
    print("CVE-TO-ATT&CK MAPPING TEST")
    print("=" * 100)
    
    # Real CVE test cases
    test_cases = [
        {
            "id": "CVE-2021-44228",
            "description": "Apache Log4j2 2.0-beta9 through 2.15.0 ... JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers...",
            "expected_techniques": ["T1190", "T1059"]
        },
        {
            "id": "CVE-2019-11043",
            "description": "In PHP versions 7.1.x below 7.1.33, 7.2.x below 7.2.24 and 7.3.x below 7.3.11 in certain configurations of FPM module for PHP, it is possible to make FPM module process a request which bypasses the authentication ... remote code execution is possible...",
            "expected_techniques": ["T1190", "T1078"]
        },
        {
            "id": "CVE-2020-14882",
            "description": "Vulnerability in Oracle WebLogic ... allows unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover...",
            "expected_techniques": ["T1190"]
        }
    ]
    
    all_passed = True
    
    for test_case in test_cases:
        print(f"\n🔍 Testing {test_case['id']}:")
        print(f"Description: {test_case['description'][:100]}...")
        
        # Create CVEResult object
        cve_result = CVEResult(
            cve_id=test_case['id'],
            description=test_case['description'],
            published="",
            last_modified="",
            vuln_status="",
            cvss_v3_score=9.8 if test_case['id'] == "CVE-2021-44228" else 8.0,
            cvss_v3_severity="CRITICAL" if test_case['id'] == "CVE-2021-44228" else "HIGH",
            cvss_v2_score=None,
            cvss_v3_vector=None,
            references=[],
            source="test"
        )
        
        # Map to ATT&CK techniques
        techniques = map_cve_to_attack(cve_result)
        
        print(f"Mapped techniques: {[t.id for t in techniques]}")
        print(f"Expected techniques: {test_case['expected_techniques']}")
        
        # Check if expected techniques are present
        technique_ids = [t.id for t in techniques]
        missing_expected = [t for t in test_case['expected_techniques'] if t not in technique_ids]
        
        if missing_expected:
            print(f"❌ FAIL: Missing expected techniques: {missing_expected}")
            all_passed = False
        else:
            print("✅ PASS: All expected techniques found")
        
        print("Found techniques:")
        for tech in techniques:
            print(f"  - {tech.id}: {tech.name} ({tech.tactic})")
    
    return all_passed


def test_scan_enrichment():
    """Test scan enrichment with mock Docker lab data."""
    print("\n" + "=" * 100)
    print("SCAN ENRICHMENT TEST")
    print("=" * 100)
    
    # Mock scan data for Docker lab
    mock_scan_results = {
        "id": "test-scan-123",
        "target": "docker-lab",
        "scan_type": "port",
        "status": "completed",
        "results": [
            {"port": 6379, "state": "open", "service": "redis", "version": "6.2"},
            {"port": 80, "state": "open", "service": "http", "version": "nginx/1.21"},
            {"port": 5432, "state": "open", "service": "postgresql", "version": "13.3"}
        ]
    }
    
    # Mock CVE results
    mock_cve_results = [
        CVEResult(
            cve_id="CVE-2021-32687",
            description="Redis vulnerability allowing remote code execution",
            published="",
            last_modified="",
            vuln_status="",
            cvss_v3_score=9.8,
            cvss_v3_severity="CRITICAL",
            cvss_v2_score=None,
            cvss_v3_vector=None,
            references=[],
            source="test"
        )
    ]
    
    # Mock detected services
    mock_detected_services = [
        ServiceDetectionResult(
            port=6379,
            state="open",
            service_name="redis",
            service_version="6.2",
            detection_method="banner",
            banner_snippet="Redis server version 6.2",
            confidence=1.0
        ),
        ServiceDetectionResult(
            port=80,
            state="open",
            service_name="http",
            service_version="nginx/1.21",
            detection_method="banner",
            banner_snippet="nginx/1.21",
            confidence=1.0
        ),
        ServiceDetectionResult(
            port=5432,
            state="open",
            service_name="postgresql",
            service_version="13.3",
            detection_method="banner",
            banner_snippet="PostgreSQL 13.3",
            confidence=1.0
        )
    ]
    
    print("🐳 Docker Lab Mock Data:")
    print(f"  - docker_redis on port 6379 with service='redis'")
    print(f"  - docker_nginx on port 80 with service='http'")
    print(f"  - docker_postgres on port 5432 with service='postgresql'")
    print(f"  - 1 CVE found for Redis (CRITICAL)")
    
    # Enrich scan with ATT&CK data
    try:
        enriched_scan = enrich_scan_with_attack(
            mock_scan_results,
            mock_cve_results,
            mock_detected_services
        )
        
        print("\n🎯 ENRICHMENT RESULTS:")
        print(f"Attack technique count: {enriched_scan.get('attack_technique_count', 0)}")
        print(f"Tactics summary: {enriched_scan.get('tactics_summary', [])}")
        
        print("\n📋 Attack Techniques:")
        for tech in enriched_scan.get('attack_techniques', []):
            cvss_info = f" (CVSS: {tech['cvss_context']})" if tech['cvss_context'] else ""
            print(f"  - {tech['technique_id']}: {tech['technique_name']} ({tech['tactic']}) - Source: {tech['source']}{cvss_info}")
        
        # Validate expected techniques are present
        expected_techniques = {
            "T1190",  # Exploit Public-Facing Application (redis, postgresql, nginx)
            "T1110",  # Brute Force (redis, postgresql)
            "T1210",  # Exploitation of Remote Services (redis, postgresql)
            "T1071.001",  # Application Layer Protocol: Web Protocols (http)
            "T1021.002",  # Remote Services: SMB/Windows Admin Shares (postgresql)
        }
        
        found_techniques = {tech['technique_id'] for tech in enriched_scan.get('attack_techniques', [])}
        
        print(f"\n✅ Found {len(found_techniques)} unique techniques")
        print(f"Expected: {len(expected_techniques)} techniques")
        
        missing = expected_techniques - found_techniques
        if missing:
            print(f"❌ Missing expected techniques: {missing}")
            return False
        else:
            print("✅ All expected techniques found")
            return True
            
    except Exception as e:
        print(f"❌ Scan enrichment failed: {e}")
        return False


def main():
    """Main validation function."""
    print("🛡️  MITRE ATT&CK MAPPING VALIDATION")
    print("=" * 100)
    
    # Test 1: Print database contents
    total_techniques, tactic_categories = print_attack_technique_db()
    
    # Test 2: CVE mapping
    cve_test_passed = test_cve_mapping()
    
    # Test 3: Scan enrichment
    enrichment_test_passed = test_scan_enrichment()
    
    # Final summary
    print("\n" + "=" * 100)
    print("📊 FINAL VALIDATION SUMMARY")
    print("=" * 100)
    print(f"Total techniques in DB: {total_techniques}")
    print(f"Unique tactic categories: {tactic_categories}")
    print(f"CVE mapping test: {'✅ PASS' if cve_test_passed else '❌ FAIL'}")
    print(f"Scan enrichment test: {'✅ PASS' if enrichment_test_passed else '❌ FAIL'}")
    
    overall_success = cve_test_passed and enrichment_test_passed
    print(f"\n🎯 OVERALL RESULT: {'✅ ALL TESTS PASSED' if overall_success else '❌ SOME TESTS FAILED'}")
    
    if overall_success:
        print("\n🎉 ATT&CK mapping implementation is working correctly!")
        print("All technique IDs are verified and mapping functions are operational.")
    else:
        print("\n⚠️  Some issues found. Please review the test failures above.")
    
    return overall_success


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
