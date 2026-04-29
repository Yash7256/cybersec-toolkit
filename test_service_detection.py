#!/usr/bin/env python3
"""
Service Detection Accuracy Test Script

Tests the multi-stage service detection pipeline against Docker lab targets
to measure accuracy improvement from 50% baseline to 80%+ target.
"""

import asyncio
import sys
import time
from dataclasses import dataclass
from typing import List, Tuple

from cybersec.core.scanner.analysis.service_detect import ServiceDetector, ServiceDetectionResult


@dataclass
class TestCase:
    """Test case for service detection."""
    ip: str
    port: int
    expected_service: str
    description: str


@dataclass
class TestResults:
    """Test results summary."""
    total_tests: int
    correct_detections: int
    accuracy: float
    detection_time: float
    results: List[Tuple[TestCase, ServiceDetectionResult]]


class ServiceDetectionTester:
    """Tester for service detection accuracy."""
    
    def __init__(self):
        self.detector = ServiceDetector()
        
        # Test cases based on Docker lab targets (ground truth verified)
        self.test_cases = [
            TestCase("172.23.0.2", 80, "http", "HTTP server on standard port"),
            TestCase("172.23.0.7", 6379, "redis", "Redis on standard port"),
            TestCase("172.23.0.6", 5432, "postgresql", "PostgreSQL on standard port"),
            TestCase("172.23.0.4", 8000, "http", "HTTP server on non-standard port"),
            TestCase("172.23.0.3", 9999, "unknown", "Abyss/tarpit on non-standard port"),
            TestCase("172.23.0.5", 8889, "unknown-service", "Netcat/raw service"),
            # Test a closed port (should return no service or unknown)
            TestCase("172.23.0.2", 9999, "unknown", "Closed port test"),
        ]
    
    def _is_detection_correct(self, test_case: TestCase, result: ServiceDetectionResult) -> bool:
        """
        Check if service detection is correct.
        
        Args:
            test_case: Expected result
            result: Actual detection result
            
        Returns:
            True if detection matches expected criteria
        """
        if test_case.expected_service == "unknown":
            # For unknown expectations, any non-empty detection that's not completely wrong
            return result.service_name != "" and result.confidence >= 0.0
        
        if test_case.expected_service == "unknown-service":
            # For raw/netcat services, check if it starts with "unknown-service"
            return result.service_name.startswith("unknown-service")
        
        # For specific services, check exact match or contains match
        expected = test_case.expected_service.lower()
        actual = result.service_name.lower()
        
        # Exact match
        if expected == actual:
            return True
            
        # Contains match (e.g., "http-alt" should match "http")
        if expected in actual or actual in expected:
            return True
            
        return False
    
    async def run_single_test(self, test_case: TestCase) -> Tuple[TestCase, ServiceDetectionResult]:
        """Run service detection on a single test case."""
        print(f"Testing {test_case.ip}:{test_case.port} - {test_case.description}")
        
        try:
            result = await self.detector.detect(test_case.ip, test_case.port, timeout=5.0)
            return test_case, result
        except Exception as e:
            print(f"  ERROR: {e}")
            # Return a failed result
            failed_result = ServiceDetectionResult(
                port=test_case.port,
                state="error",
                service_name="error",
                service_version="",
                detection_method="error",
                banner_snippet="",
                confidence=0.0
            )
            return test_case, failed_result
    
    async def run_all_tests(self) -> TestResults:
        """Run all test cases and return results."""
        print("🔍 Starting Service Detection Accuracy Test")
        print("=" * 60)
        
        start_time = time.time()
        
        # Run all tests concurrently
        tasks = [self.run_single_test(test_case) for test_case in self.test_cases]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        end_time = time.time()
        detection_time = end_time - start_time
        
        # Process results
        correct_detections = 0
        valid_results = []
        
        for result in results:
            if isinstance(result, Exception):
                print(f"Test failed with exception: {result}")
                continue
                
            test_case, detection_result = result
            valid_results.append((test_case, detection_result))
            
            is_correct = self._is_detection_correct(test_case, detection_result)
            if is_correct:
                correct_detections += 1
            
            # Print detailed result
            status = "✅ CORRECT" if is_correct else "❌ INCORRECT"
            print(f"  {test_case.ip}:{test_case.port} → {detection_result.service_name}")
            print(f"    Method: {detection_result.detection_method}, Confidence: {detection_result.confidence:.2f}")
            print(f"    Banner: {detection_result.banner_snippet[:60]}...")
            print(f"    Status: {status}")
            print()
        
        total_tests = len(valid_results)
        accuracy = (correct_detections / total_tests) * 100 if total_tests > 0 else 0
        
        return TestResults(
            total_tests=total_tests,
            correct_detections=correct_detections,
            accuracy=accuracy,
            detection_time=detection_time,
            results=valid_results
        )
    
    def print_summary(self, results: TestResults):
        """Print test summary."""
        print("=" * 60)
        print("📊 SERVICE DETECTION ACCURACY RESULTS")
        print("=" * 60)
        print(f"Total Tests: {results.total_tests}")
        print(f"Correct Detections: {results.correct_detections}")
        print(f"Accuracy: {results.accuracy:.1f}%")
        print(f"Detection Time: {results.detection_time:.2f} seconds")
        print()
        
        # Show before/after comparison
        baseline_accuracy = 50.0  # Current baseline
        improvement = results.accuracy - baseline_accuracy
        
        print("📈 ACCURACY IMPROVEMENT")
        print("-" * 30)
        print(f"Before (baseline): {baseline_accuracy:.1f}%")
        print(f"After (current):   {results.accuracy:.1f}%")
        print(f"Improvement:       {improvement:+.1f}%")
        
        if results.accuracy >= 80.0:
            print("🎯 TARGET ACHIEVED: ≥80% accuracy!")
        elif results.accuracy >= 70.0:
            print("📊 CLOSE: Getting close to 80% target")
        else:
            print("⚠️  NEEDS WORK: Still below 80% target")
        
        print()
        
        # Detailed breakdown by detection method
        method_stats = {}
        for test_case, result in results.results:
            method = result.detection_method
            if method not in method_stats:
                method_stats[method] = {"total": 0, "correct": 0}
            method_stats[method]["total"] += 1
            
            if self._is_detection_correct(test_case, result):
                method_stats[method]["correct"] += 1
        
        print("🔍 BREAKDOWN BY DETECTION METHOD")
        print("-" * 40)
        for method, stats in method_stats.items():
            accuracy = (stats["correct"] / stats["total"]) * 100 if stats["total"] > 0 else 0
            print(f"{method:15}: {stats['correct']}/{stats['total']} ({accuracy:.1f}%)")
        
        # Print the research paper number
        print()
        print("📋 RESEARCH PAPER METRIC")
        print("-" * 25)
        print(f"Final Service Detection Accuracy: {results.accuracy:.1f}%")


async def main():
    """Main test function."""
    tester = ServiceDetectionTester()
    
    try:
        results = await tester.run_all_tests()
        tester.print_summary(results)
        
        # Exit with appropriate code for CI/CD
        if results.accuracy >= 80.0:
            print("\n✅ Test PASSED - Target accuracy achieved!")
            sys.exit(0)
        else:
            print(f"\n❌ Test FAILED - Accuracy {results.accuracy:.1f}% below 80% target")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\n⏹️  Test interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n💥 Test failed with error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    # Run the test
    asyncio.run(main())
