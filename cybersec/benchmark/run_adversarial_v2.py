"""
Adversarial Evaluation Runner V2

Runs the generated adversarial dataset against the actual service detector
and produces comprehensive metrics, failure reports, and summary tables.
"""
import asyncio
import json
import sys
import os
import time
from typing import Dict, List, Any
from collections import defaultdict
from datetime import datetime
import csv

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cybersec.core.scanner.analysis.service_detect import ServiceDetector
from cybersec.benchmark.adversarial_dataset_v2 import AdversarialTestCase


class AdversarialEvaluator:
    """Run adversarial dataset against service detector."""
    
    def __init__(self, dataset_file: str = "adversarial_dataset_v2.json"):
        self.detector = ServiceDetector()
        self.dataset_file = dataset_file
        self.results = []
    
    def load_dataset(self) -> List[Dict[str, Any]]:
        """Load adversarial dataset."""
        print(f"Loading dataset from {self.dataset_file}...")
        with open(self.dataset_file, "r") as f:
            dataset = json.load(f)
        print(f"  Loaded {len(dataset)} test cases")
        return dataset
    
    async def run_single_test(self, test_case: Dict[str, Any]) -> Dict[str, Any]:
        """Run a single test case against the detector."""
        start_time = time.time()
        
        try:
            result = await self.detector.detect(
                test_case["host"],
                test_case["port"],
                timeout=2.0
            )
            
            latency_ms = (time.time() - start_time) * 1000
            
            # Determine if match
            expected = test_case.get("expected_service", "unknown")
            detected = result.name
            match = detected.lower() == expected.lower()
            
            return {
                "test_id": test_case.get("id", ""),
                "host": test_case["host"],
                "port": test_case["port"],
                "expected": expected,
                "detected": detected,
                "confidence": result.confidence,
                "match": match,
                "scenario_type": test_case.get("scenario_type", "unknown"),
                "scenario_subtype": test_case.get("scenario_subtype", ""),
                "difficulty": test_case.get("difficulty", "medium"),
                "latency_ms": round(latency_ms, 2),
                "banner": result.banner[:100] if result.banner else None,
                "error": None,
            }
            
        except asyncio.TimeoutError:
            return {
                "test_id": test_case.get("id", ""),
                "host": test_case["host"],
                "port": test_case["port"],
                "expected": test_case.get("expected_service", "unknown"),
                "detected": "timeout",
                "confidence": 0,
                "match": False,
                "scenario_type": test_case.get("scenario_type", "unknown"),
                "scenario_subtype": test_case.get("scenario_subtype", ""),
                "difficulty": test_case.get("difficulty", "medium"),
                "latency_ms": (time.time() - start_time) * 1000,
                "error": "timeout",
            }
        except ConnectionRefusedError:
            expected = test_case.get("expected_service", "unknown")
            detected = "filtered" if expected == "filtered" else "unknown"
            match = detected.lower() == expected.lower()
            
            return {
                "test_id": test_case.get("id", ""),
                "host": test_case["host"],
                "port": test_case["port"],
                "expected": expected,
                "detected": detected,
                "confidence": 0,
                "match": match,
                "scenario_type": test_case.get("scenario_type", "unknown"),
                "scenario_subtype": test_case.get("scenario_subtype", ""),
                "difficulty": test_case.get("difficulty", "medium"),
                "latency_ms": (time.time() - start_time) * 1000,
                "error": "connection_refused",
            }
        except Exception as e:
            return {
                "test_id": test_case.get("id", ""),
                "host": test_case["host"],
                "port": test_case["port"],
                "expected": test_case.get("expected_service", "unknown"),
                "detected": "error",
                "confidence": 0,
                "match": False,
                "scenario_type": test_case.get("scenario_type", "unknown"),
                "scenario_subtype": test_case.get("scenario_subtype", ""),
                "difficulty": test_case.get("difficulty", "medium"),
                "latency_ms": (time.time() - start_time) * 1000,
                "error": str(e),
            }
    
    async def run_evaluation(self, max_tests: int = None, parallel: bool = True, max_concurrent: int = 50) -> List[Dict[str, Any]]:
        """Run full evaluation."""
        dataset = self.load_dataset()
        
        if max_tests:
            dataset = dataset[:max_tests]
        
        print(f"\nRunning evaluation on {len(dataset)} test cases...")
        print(f"Parallel: {parallel}, Max concurrent: {max_concurrent}\n")
        
        semaphore = asyncio.Semaphore(max_concurrent)
        all_results = []
        completed = 0
        start_time = time.time()
        
        async def run_with_semaphore(test_case):
            async with semaphore:
                return await self.run_single_test(test_case)
        
        if parallel:
            tasks = [run_with_semaphore(tc) for tc in dataset]
            for coro in asyncio.as_completed(tasks):
                result = await coro
                all_results.append(result)
                completed += 1
                
                if completed % 500 == 0:
                    elapsed = time.time() - start_time
                    rate = completed / elapsed
                    print(f"  Completed {completed}/{len(dataset)} ({completed/len(dataset)*100:.1f}%) - Rate: {rate:.1f} tests/sec")
        else:
            for test_case in dataset:
                result = await self.run_single_test(test_case)
                all_results.append(result)
                completed += 1
                
                if completed % 100 == 0:
                    print(f"  Completed {completed}/{len(dataset)}")
        
        elapsed = time.time() - start_time
        print(f"\nEvaluation complete in {elapsed:.2f}s")
        print(f"Total tests: {len(all_results)}")
        print(f"Average rate: {len(all_results)/elapsed:.1f} tests/sec\n")
        
        self.results = all_results
        return all_results
    
    def compute_comprehensive_metrics(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Compute all required metrics."""
        import math
        
        total = len(results)
        correct = sum(1 for r in results if r["match"])
        overall_accuracy = (correct / total * 100) if total > 0 else 0
        
        # === PER-SCENARIO METRICS ===
        by_scenario = defaultdict(lambda: {
            "correct": 0, "total": 0, "confidences": [],
            "false_positives": 0, "false_negatives": 0,
            "unknown_count": 0, "misclassifications": defaultdict(int)
        })
        
        for r in results:
            scenario = r["scenario_type"]
            by_scenario[scenario]["total"] += 1
            
            if r["match"]:
                by_scenario[scenario]["correct"] += 1
            
            by_scenario[scenario]["confidences"].append(r["confidence"])
            
            if r["detected"] not in ["unknown", "filtered", "timeout", "error"] and r["expected"] in ["unknown", "filtered"]:
                by_scenario[scenario]["false_positives"] += 1
            
            if r["detected"] in ["unknown", "filtered"] and r["expected"] not in ["unknown", "filtered"]:
                by_scenario[scenario]["false_negatives"] += 1
            
            if r["detected"] == "unknown":
                by_scenario[scenario]["unknown_count"] += 1
            
            if not r["match"]:
                by_scenario[scenario]["misclassifications"][r["detected"]] += 1
        
        scenario_metrics = {}
        for scenario, stats in by_scenario.items():
            confidences = stats["confidences"]
            avg_conf = sum(confidences) / len(confidences) if confidences else 0
            std_conf = (
                math.sqrt(sum((c - avg_conf) ** 2 for c in confidences) / len(confidences))
                if confidences else 0
            )
            low_conf_count = sum(1 for c in confidences if c < 30)
            accuracy = (stats["correct"] / stats["total"] * 100) if stats["total"] > 0 else 0
            
            scenario_metrics[scenario] = {
                "accuracy": round(accuracy, 2),
                "total": stats["total"],
                "correct": stats["correct"],
                "incorrect": stats["total"] - stats["correct"],
                "false_positives": stats["false_positives"],
                "false_negatives": stats["false_negatives"],
                "unknown_classification_rate": round(stats["unknown_count"] / stats["total"] * 100, 2) if stats["total"] > 0 else 0,
                "confidence": {
                    "mean": round(avg_conf, 2),
                    "std": round(std_conf, 2),
                    "low_confidence_rate": round(low_conf_count / len(confidences) * 100, 2) if confidences else 0,
                    "min": min(confidences) if confidences else 0,
                    "max": max(confidences) if confidences else 0,
                },
                "top_misclassifications": dict(sorted(stats["misclassifications"].items(), key=lambda x: x[1], reverse=True)[:5]),
            }
        
        # === CONFUSION MATRIX ===
        confusion = defaultdict(lambda: defaultdict(int))
        for r in results:
            confusion[r["expected"]][r["detected"]] += 1
        
        # === HIGH CONFIDENCE FAILURES (CRITICAL BUGS) ===
        high_conf_failures = [
            r for r in results
            if r["confidence"] > 50 and not r["match"]
        ]
        
        # === CONFIDENCE DISTRIBUTION ===
        all_confidences = [r["confidence"] for r in results]
        avg_confidence = sum(all_confidences) / len(all_confidences) if all_confidences else 0
        
        # === LATENCY ANALYSIS ===
        latencies = [r["latency_ms"] for r in results if r.get("latency_ms", 0) > 0]
        avg_latency = sum(latencies) / len(latencies) if latencies else 0
        
        # === DIFFICULTY BREAKDOWN ===
        by_difficulty = defaultdict(lambda: {"correct": 0, "total": 0})
        for r in results:
            by_difficulty[r["difficulty"]]["total"] += 1
            if r["match"]:
                by_difficulty[r["difficulty"]]["correct"] += 1
        
        difficulty_metrics = {}
        for diff, stats in by_difficulty.items():
            acc = (stats["correct"] / stats["total"] * 100) if stats["total"] > 0 else 0
            difficulty_metrics[diff] = {
                "accuracy": round(acc, 2),
                "total": stats["total"],
                "correct": stats["correct"],
            }
        
        metrics = {
            "summary": {
                "total_cases": total,
                "overall_accuracy": round(overall_accuracy, 2),
                "correct": correct,
                "incorrect": total - correct,
                "evaluation_timestamp": datetime.now().isoformat(),
            },
            "per_scenario": scenario_metrics,
            "confusion_matrix": {k: dict(v) for k, v in confusion.items()},
            "high_confidence_failures": {
                "count": len(high_conf_failures),
                "rate": round(len(high_conf_failures) / total * 100, 2) if total > 0 else 0,
                "description": "Cases where confidence > 50 BUT classification is wrong (CRITICAL BUG)",
            },
            "confidence_distribution": {
                "mean": round(avg_confidence, 2),
                "all_observations": len(all_confidences),
            },
            "latency": {
                "average_ms": round(avg_latency, 2),
                "total_observations": len(latencies),
            },
            "difficulty_breakdown": difficulty_metrics,
        }
        
        return metrics
    
    def identify_failure_cases(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify and prioritize failure cases."""
        failures = []
        
        for r in results:
            failure_reasons = []
            severity = "LOW"
            
            # CRITICAL: High confidence but wrong
            if r["confidence"] > 50 and not r["match"]:
                failure_reasons.append("CRITICAL: High confidence wrong classification")
                severity = "CRITICAL"
            
            # HIGH: Consistent misclassification (not unknown/filtered)
            if not r["match"] and r["detected"] not in ["unknown", "filtered", "timeout", "error"]:
                if severity != "CRITICAL":
                    failure_reasons.append("HIGH: Misclassified to wrong service")
                    severity = "HIGH"
            
            # MEDIUM: False positive
            if r["detected"] not in ["unknown", "filtered", "timeout", "error"] and r["expected"] in ["unknown", "filtered"]:
                if severity == "LOW":
                    failure_reasons.append("MEDIUM: False positive")
                    severity = "MEDIUM"
            
            if failure_reasons:
                failures.append({
                    "test_id": r["test_id"],
                    "port": r["port"],
                    "expected": r["expected"],
                    "detected": r["detected"],
                    "confidence": r["confidence"],
                    "scenario_type": r["scenario_type"],
                    "scenario_subtype": r.get("scenario_subtype", ""),
                    "difficulty": r["difficulty"],
                    "failure_reasons": failure_reasons,
                    "severity": severity,
                    "latency_ms": r.get("latency_ms", 0),
                })
        
        # Sort by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        failures.sort(key=lambda x: severity_order.get(x["severity"], 4))
        
        return failures
    
    def generate_summary_table(self, metrics: Dict[str, Any]) -> str:
        """Generate summary table."""
        table = "\n" + "=" * 100 + "\n"
        table += "SCENARIO SUMMARY TABLE\n"
        table += "=" * 100 + "\n"
        table += f"{'Scenario':<35} | {'Accuracy':>10} | {'Avg Confidence':>15} | {'Failure Mode':<25} | {'Total':>6}\n"
        table += "-" * 100 + "\n"
        
        for scenario, stats in sorted(metrics.get("per_scenario", {}).items(), key=lambda x: x[1]["accuracy"]):
            accuracy = stats["accuracy"]
            avg_conf = stats["confidence"]["mean"]
            total = stats["total"]
            
            # Determine failure mode
            if accuracy < 30:
                failure_mode = "Critical failure"
            elif accuracy < 50:
                failure_mode = "Low accuracy"
            elif stats["false_positives"] > stats["false_negatives"] * 2:
                failure_mode = "High FP rate"
            elif stats["false_negatives"] > stats["false_positives"] * 2:
                failure_mode = "High FN rate"
            elif stats["confidence"]["std"] > 30:
                failure_mode = "Unstable confidence"
            else:
                failure_mode = "Stable"
            
            table += f"{scenario:<35} | {accuracy:>9.1f}% | {avg_conf:>14.1f} | {failure_mode:<25} | {total:>6}\n"
        
        table += "=" * 100 + "\n"
        return table
    
    def export_csv(self, results: List[Dict[str, Any]], filename: str = "adversarial_results_v2.csv"):
        """Export results to CSV."""
        with open(filename, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=[
                "test_id", "host", "port", "expected", "detected", "confidence",
                "match", "scenario_type", "scenario_subtype", "difficulty",
                "latency_ms", "error", "banner"
            ])
            writer.writeheader()
            writer.writerows(results)
        
        print(f"CSV exported to: {filename}")
    
    def save_outputs(self, metrics: Dict[str, Any], failures: List[Dict[str, Any]], results: List[Dict[str, Any]]):
        """Save all output files."""
        # 1. Metrics report
        report_file = "adversarial_report_v2.json"
        with open(report_file, "w") as f:
            json.dump(metrics, f, indent=2, default=str)
        print(f"Metrics report saved to: {report_file}")
        
        # 2. Failure cases
        failure_file = "failure_cases_v2.json"
        with open(failure_file, "w") as f:
            json.dump(failures, f, indent=2, default=str)
        print(f"Failure cases saved to: {failure_file}")
        
        # 3. CSV export
        self.export_csv(results)
        
        # 4. Print summary table
        summary_table = self.generate_summary_table(metrics)
        print(summary_table)


async def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Run adversarial evaluation V2")
    parser.add_argument("--dataset", type=str, default="adversarial_dataset_v2.json", help="Dataset file")
    parser.add_argument("--max-tests", type=int, default=None, help="Limit tests for quick run")
    parser.add_argument("--sequential", action="store_true", help="Run sequentially instead of parallel")
    parser.add_argument("--concurrent", type=int, default=50, help="Max concurrent tests")
    args = parser.parse_args()
    
    evaluator = AdversarialEvaluator(dataset_file=args.dataset)
    
    # Run evaluation
    results = await evaluator.run_evaluation(
        max_tests=args.max_tests,
        parallel=not args.sequential,
        max_concurrent=args.concurrent
    )
    
    # Compute metrics
    print("Computing comprehensive metrics...")
    metrics = evaluator.compute_comprehensive_metrics(results)
    
    # Identify failures
    print("Identifying failure cases...")
    failures = evaluator.identify_failure_cases(results)
    
    # Save all outputs
    print("\nSaving outputs...")
    evaluator.save_outputs(metrics, failures, results)
    
    # Print key findings
    print("\n" + "=" * 100)
    print("KEY FINDINGS")
    print("=" * 100)
    
    s = metrics["summary"]
    print(f"\nOverall Accuracy: {s['overall_accuracy']:.1f}% ({s['correct']}/{s['total']})")
    
    hcf = metrics["high_confidence_failures"]
    print(f"High-Confidence Failures: {hcf['count']} ({hcf['rate']:.1f}%) ❗")
    
    print(f"\nTotal Failure Cases: {len(failures)}")
    critical = sum(1 for f in failures if f["severity"] == "CRITICAL")
    high = sum(1 for f in failures if f["severity"] == "HIGH")
    print(f"  CRITICAL: {critical}")
    print(f"  HIGH: {high}")
    
    # Top 5 worst scenarios
    print("\nTop 5 Worst Performing Scenarios:")
    sorted_scenarios = sorted(metrics["per_scenario"].items(), key=lambda x: x[1]["accuracy"])
    for scenario, stats in sorted_scenarios[:5]:
        print(f"  {scenario}: {stats['accuracy']:.1f}% accuracy ({stats['total']} cases)")
    
    print("\n" + "=" * 100)
    print("EVALUATION COMPLETE")
    print("=" * 100)
    
    return metrics


if __name__ == "__main__":
    asyncio.run(main())
