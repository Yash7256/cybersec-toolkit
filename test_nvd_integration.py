#!/usr/bin/env python3
"""
NVD API 2.0 Integration Test Script

This script tests the real NVD API 2.0 integration with live HTTP requests.
It validates CVE fetching, searching, and service-to-CVE mapping functionality.

IMPORTANT: This script makes REAL HTTP requests to NVD's live API.
Print each result with all fields. Do not mock or fake any responses.
The numbers printed by this script are what go in the research paper.
"""

import asyncio
import sys
import time
from pathlib import Path
from typing import List

# Add the cybersec package to Python path
sys.path.insert(0, str(Path(__file__).parent / "cybersec"))

from cybersec.core.security.nvd_client import NVDClient, EnhancedCVELookup, CVEResult


class NVDIntegrationTester:
    """Tester for NVD API 2.0 integration."""
    
    def __init__(self):
        self.client = NVDClient()  # No API key, so 6s delay between calls
        self.api_calls_made = 0
        self.cache_hits = 0
        
    async def _track_api_call(self, description: str):
        """Track and log API calls."""
        self.api_calls_made += 1
        print(f"\n📡 API Call #{self.api_calls_made}: {description}")
        print("-" * 50)
    
    def _print_cve_result(self, cve: CVEResult, title: str = ""):
        """Print a CVE result with all fields."""
        if title:
            print(f"\n🔍 {title}")
            print("-" * len(title))
        
        print(f"CVE ID:           {cve.cve_id}")
        print(f"Description:       {cve.description[:100]}{'...' if len(cve.description) > 100 else ''}")
        print(f"Published:         {cve.published}")
        print(f"Last Modified:     {cve.last_modified}")
        print(f"Vulnerability Status: {cve.vuln_status}")
        print(f"CVSS v3 Score:    {cve.cvss_v3_score}")
        print(f"CVSS v3 Severity: {cve.cvss_v3_severity}")
        print(f"CVSS v2 Score:    {cve.cvss_v2_score}")
        print(f"CVSS v3 Vector:    {cve.cvss_v3_vector}")
        print(f"References:        {len(cve.references)} URLs")
        for i, ref in enumerate(cve.references[:3], 1):
            print(f"  {i}. {ref}")
        if len(cve.references) > 3:
            print(f"  ... and {len(cve.references) - 3} more")
        print(f"Source:            {cve.source}")
    
    def _print_cve_list(self, cves: List[CVEResult], title: str = "", limit: int = None):
        """Print a list of CVEs."""
        if title:
            print(f"\n📋 {title}")
            print("-" * len(title))
        
        if not cves:
            print("❌ No CVEs found")
            return
        
        cves_to_show = cves[:limit] if limit else cves
        
        for i, cve in enumerate(cves_to_show, 1):
            print(f"\n{i}. {cve.cve_id}")
            print(f"   Score: {cve.cvss_v3_score or cve.cvss_v2_score or 'N/A'} | "
                  f"Severity: {cve.cvss_v3_severity or 'UNKNOWN'}")
            print(f"   Description: {cve.description[:80]}{'...' if len(cve.description) > 80 else ''}")
        
        if limit and len(cves) > limit:
            print(f"\n... and {len(cves) - limit} more CVEs found")
    
    async def test_1_fetch_log4shell(self):
        """Test 1: Fetch CVE-2021-44228 (Log4Shell) by ID."""
        await self._track_api_call("Fetch CVE-2021-44228 (Log4Shell) by ID")
        
        start_time = time.time()
        cve = await self.client.get_cve_by_id("CVE-2021-44228")
        end_time = time.time()
        
        if cve:
            self._print_cve_result(cve, "CVE-2021-44228 (Log4Shell) Details")
            print(f"⏱️  Request completed in {end_time - start_time:.2f} seconds")
        else:
            print("❌ CVE-2021-44228 not found")
        
        return cve is not None
    
    async def test_2_search_redis_cves(self):
        """Test 2: Search for Redis CVEs and print top 3 by CVSS score."""
        await self._track_api_call("Search for Redis CVEs")
        
        start_time = time.time()
        cves = await self.client.search_cves_by_keyword("redis", max_results=20)
        end_time = time.time()
        
        # Sort by CVSS score (highest first)
        cves.sort(key=lambda x: (x.cvss_v3_score or x.cvss_v2_score or 0.0), reverse=True)
        
        self._print_cve_list(cves, "Redis CVEs (Top 3 by CVSS Score)", limit=3)
        print(f"⏱️  Request completed in {end_time - start_time:.2f} seconds")
        print(f"📊 Total Redis CVEs found: {len(cves)}")
        
        return len(cves) > 0
    
    async def test_3_search_postgresql_cves(self):
        """Test 3: Search for PostgreSQL CVEs and print top 3 by CVSS score."""
        await self._track_api_call("Search for PostgreSQL CVEs")
        
        start_time = time.time()
        cves = await self.client.search_cves_by_keyword("postgresql", max_results=20)
        end_time = time.time()
        
        # Sort by CVSS score (highest first)
        cves.sort(key=lambda x: (x.cvss_v3_score or x.cvss_v2_score or 0.0), reverse=True)
        
        self._print_cve_list(cves, "PostgreSQL CVEs (Top 3 by CVSS Score)", limit=3)
        print(f"⏱️  Request completed in {end_time - start_time:.2f} seconds")
        print(f"📊 Total PostgreSQL CVEs found: {len(cves)}")
        
        return len(cves) > 0
    
    async def test_4_service_lookup_nginx(self):
        """Test 4: Call lookup_cves_for_service('nginx', '') and print count + top result."""
        await self._track_api_call("Service-to-CVE lookup for nginx")
        
        start_time = time.time()
        cves = await self.client.lookup_cves_for_service("nginx", "")
        end_time = time.time()
        
        print(f"\n🔧 Nginx Service CVE Lookup Results")
        print("-" * 40)
        print(f"📊 Total CVEs found: {len(cves)}")
        print(f"⏱️  Request completed in {end_time - start_time:.2f} seconds")
        
        if cves:
            print(f"🎯 Top CVE (highest CVSS score):")
            top_cve = cves[0]  # Already sorted by CVSS score
            self._print_cve_result(top_cve, "Top Nginx CVE")
        
        return len(cves) > 0
    
    async def test_5_rate_limiting(self):
        """Test 5: Verify rate limiting is working (make 2 quick calls)."""
        print(f"\n⏱️  Testing Rate Limiting")
        print("-" * 30)
        
        start_time = time.time()
        
        # First call
        await self._track_api_call("First quick call (rate limit test)")
        await self.client.search_cves_by_keyword("test", max_results=5)
        
        # Second call immediately (should be delayed)
        await self._track_api_call("Second quick call (should be rate limited)")
        await self.client.search_cves_by_keyword("test2", max_results=5)
        
        end_time = time.time()
        total_time = end_time - start_time
        
        print(f"\n📊 Rate Limiting Test Results:")
        print(f"Total time for 2 calls: {total_time:.2f} seconds")
        print(f"Expected minimum time: ~{self.client.rate_limit_delay:.1f} seconds")
        print(f"Rate limiting working: {'✅ YES' if total_time >= self.client.rate_limit_delay - 1 else '❌ NO'}")
        
        return total_time >= self.client.rate_limit_delay - 1
    
    async def run_all_tests(self):
        """Run all NVD integration tests."""
        print("🚀 Starting NVD API 2.0 Integration Tests")
        print("=" * 60)
        print(f"📋 Configuration:")
        print(f"   - API Key: {'Yes' if self.client.api_key else 'No'}")
        print(f"   - Rate Limit Delay: {self.client.rate_limit_delay}s")
        print(f"   - Base URL: {self.client.base_url}")
        print(f"   - Min CVSS Score: 5.0")
        print(f"   - Max Results per Service: 10")
        print()
        
        test_results = []
        
        try:
            # Test 1: Fetch Log4Shell
            result1 = await self.test_1_fetch_log4shell()
            test_results.append(("CVE-2021-44228 Fetch", result1))
            
            # Test 2: Redis CVEs
            result2 = await self.test_2_search_redis_cves()
            test_results.append(("Redis CVE Search", result2))
            
            # Test 3: PostgreSQL CVEs
            result3 = await self.test_3_search_postgresql_cves()
            test_results.append(("PostgreSQL CVE Search", result3))
            
            # Test 4: Nginx service lookup
            result4 = await self.test_4_service_lookup_nginx()
            test_results.append(("Nginx Service Lookup", result4))
            
            # Test 5: Rate limiting
            result5 = await self.test_5_rate_limiting()
            test_results.append(("Rate Limiting", result5))
            
        except Exception as e:
            print(f"\n💥 Test suite failed with error: {e}")
            return False
        
        # Print summary
        print("\n" + "=" * 60)
        print("📊 NVD INTEGRATION TEST SUMMARY")
        print("=" * 60)
        
        passed_tests = sum(1 for _, result in test_results if result)
        total_tests = len(test_results)
        
        for test_name, result in test_results:
            status = "✅ PASS" if result else "❌ FAIL"
            print(f"{test_name:<25}: {status}")
        
        print(f"\n📈 Overall Results:")
        print(f"Tests Passed: {passed_tests}/{total_tests}")
        print(f"Success Rate: {(passed_tests/total_tests)*100:.1f}%")
        print(f"Total API Calls Made: {self.api_calls_made}")
        print(f"Total Cache Hits: {self.cache_hits}")
        
        # Research paper metrics
        print(f"\n📋 RESEARCH PAPER METRICS:")
        print("-" * 30)
        print(f"CVE-2021-44228 Found: {'Yes' if test_results[0][1] else 'No'}")
        print(f"Redis CVEs Found: {'Yes' if test_results[1][1] else 'No'}")
        print(f"PostgreSQL CVEs Found: {'Yes' if test_results[2][1] else 'No'}")
        print(f"Nginx Service CVEs: {'Yes' if test_results[3][1] else 'No'}")
        print(f"Rate Limiting Working: {'Yes' if test_results[4][1] else 'No'}")
        print(f"Total API Requests: {self.api_calls_made}")
        
        return passed_tests == total_tests


async def main():
    """Main test function."""
    tester = NVDIntegrationTester()
    
    try:
        success = await tester.run_all_tests()
        
        if success:
            print("\n🎉 ALL TESTS PASSED - NVD integration working correctly!")
            sys.exit(0)
        else:
            print("\n⚠️  SOME TESTS FAILED - Check implementation")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\n⏹️  Tests interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n💥 Test suite failed with error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    # Run the NVD integration tests
    asyncio.run(main())
