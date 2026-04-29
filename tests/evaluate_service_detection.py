#!/usr/bin/env python3
"""
Service Detection Evaluation Script.
Evaluates service detection accuracy against ground truth using multi-level metrics.
"""
import asyncio
import json
import sys
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from collections import defaultdict


def match_service(pred, gt):
    """Match service name."""
    return pred.get("name", "").lower() == gt.get("service", "").lower()


def match_product(pred, gt):
    """Match product name."""
    pred_product = pred.get("product", "").lower() if pred.get("product") else ""
    gt_product = gt.get("product", "").lower() if gt.get("product") else ""
    if not pred_product or not gt_product:
        return False
    return pred_product == gt_product


def match_version(pred, gt):
    """Match version (prefix match)."""
    pred_version = pred.get("version")
    gt_version = gt.get("version")
    if not pred_version or not gt_version:
        return False
    return str(pred_version).startswith(str(gt_version))


class ServiceDetectionEvaluator:
    """
    Evaluates service detection accuracy with multi-level metrics.
    """
    
    def __init__(self):
        self.results: List[Dict[str, Any]] = []
        self.ground_truth: List[Dict[str, Any]] = []
    
    async def evaluate(
        self,
        ground_truth: List[Dict[str, Any]],
        detector_func,
        timeout: float = 5.0
    ) -> Dict[str, Any]:
        """
        Evaluate service detection against ground truth.
        """
        self.ground_truth = ground_truth
        
        print(f"Evaluating {len(ground_truth)} targets...")
        
        for gt in ground_truth:
            host = gt["host"]
            port = gt["port"]
            
            try:
                result = await asyncio.wait_for(
                    detector_func(host, port),
                    timeout=timeout
                )
                
                self.results.append({
                    "host": host,
                    "port": port,
                    "gt": gt,
                    "detected": result,
                    "state": result.get("state", "unknown"),
                })
                
                status = "✓" if result.get("state") == "open" else "✗"
                print(f"  {status} {host}:{port} - state: {result.get('state')}, service: {result.get('name')}")
                
            except asyncio.TimeoutError:
                self.results.append({
                    "host": host,
                    "port": port,
                    "gt": gt,
                    "detected": {"state": "timeout"},
                    "state": "timeout",
                })
                print(f"  ✗ {host}:{port} - TIMEOUT")
                
            except Exception as e:
                self.results.append({
                    "host": host,
                    "port": port,
                    "gt": gt,
                    "detected": {"state": "error", "error": str(e)},
                    "state": "error",
                })
                print(f"  ✗ {host}:{port} - ERROR: {e}")
        
        return self.compute_metrics()
    
    def compute_metrics(self) -> Dict[str, Any]:
        """Compute multi-level metrics (service, product, version)."""
        
        # Initialize metrics per level
        metrics = {
            "service": {"tp": 0, "fp": 0, "fn": 0, "tn": 0},
            "product": {"tp": 0, "fp": 0, "fn": 0, "tn": 0},
            "version": {"tp": 0, "fp": 0, "fn": 0, "tn": 0},
        }
        
        detailed = []
        
        for r in self.results:
            pred = r["detected"]
            gt = r["gt"]
            pred_state = pred.get("state", "unknown")
            gt_state = gt.get("state", "unknown")
            
            entry = {
                "host": r["host"],
                "port": r["port"],
                "gt_state": gt_state,
                "pred_state": pred_state,
                "gt_service": gt.get("service"),
                "pred_service": pred.get("name"),
                "gt_product": gt.get("product"),
                "pred_product": pred.get("product"),
                "gt_version": gt.get("version"),
                "pred_version": pred.get("version"),
                "service_match": None,
                "product_match": None,
                "version_match": None,
            }
            
            # Both open - evaluate detection
            if pred_state == "open" and gt_state == "open":
                
                # SERVICE
                if match_service(pred, gt):
                    metrics["service"]["tp"] += 1
                    entry["service_match"] = True
                else:
                    metrics["service"]["fp"] += 1
                    metrics["service"]["fn"] += 1
                    entry["service_match"] = False
                
                # PRODUCT
                if pred.get("product"):
                    if match_product(pred, gt):
                        metrics["product"]["tp"] += 1
                        entry["product_match"] = True
                    else:
                        metrics["product"]["fp"] += 1
                        metrics["product"]["fn"] += 1
                        entry["product_match"] = False
                else:
                    metrics["product"]["fn"] += 1
                    entry["product_match"] = False
                
                # VERSION
                if pred.get("version"):
                    if match_version(pred, gt):
                        metrics["version"]["tp"] += 1
                        entry["version_match"] = True
                    else:
                        metrics["version"]["fp"] += 1
                        metrics["version"]["fn"] += 1
                        entry["version_match"] = False
                else:
                    metrics["version"]["fn"] += 1
                    entry["version_match"] = False
            
            # Pred closed, GT open - miss
            elif pred_state != "open" and gt_state == "open":
                metrics["service"]["fn"] += 1
                metrics["product"]["fn"] += 1
                metrics["version"]["fn"] += 1
                entry["service_match"] = False
                entry["product_match"] = False
                entry["version_match"] = False
            
            # Both closed - correct rejection
            elif pred_state != "open" and gt_state != "open":
                metrics["service"]["tn"] += 1
                metrics["product"]["tn"] += 1
                metrics["version"]["tn"] += 1
                entry["service_match"] = True
                entry["product_match"] = True
                entry["version_match"] = True
            
            # Pred open, GT closed - false positive
            elif pred_state == "open" and gt_state != "open":
                metrics["service"]["fp"] += 1
                metrics["product"]["fp"] += 1
                metrics["version"]["fp"] += 1
                entry["service_match"] = False
                entry["product_match"] = False
                entry["version_match"] = False
            
            detailed.append(entry)
        
        # Compute precision, recall, F1 per level
        results = {}
        for level in ["service", "product", "version"]:
            tp = metrics[level]["tp"]
            fp = metrics[level]["fp"]
            fn = metrics[level]["fn"]
            
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0
            f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
            
            results[level] = {
                "tp": tp,
                "fp": fp,
                "fn": fn,
                "precision": round(precision, 3),
                "recall": round(recall, 3),
                "f1": round(f1, 3),
            }
        
        results["detailed"] = detailed
        
        return results
    
    def print_summary(self, results: Dict[str, Any]) -> None:
        """Print human-readable summary."""
        
        print("\n" + "=" * 60)
        print("SERVICE DETECTION EVALUATION RESULTS")
        print("=" * 60)
        
        for level in ["service", "product", "version"]:
            m = results[level]
            print(f"\n{level.upper()}:")
            print(f"  TP: {m['tp']}, FP: {m['fp']}, FN: {m['fn']}")
            print(f"  Precision: {m['precision']*100:.1f}%")
            print(f"  Recall:    {m['recall']*100:.1f}%")
            print(f"  F1 Score: {m['f1']*100:.1f}%")
        
        print("\n" + "=" * 60)


async def run_evaluation():
    """Main evaluation runner."""
    
    # Import ground truth - use only externally reachable hosts
    from cybersec.benchmark.datasets import load_services
    
    services = load_services()
    
    # Convert to evaluation format - only use known external hosts
    ground_truth = []
    for host in ["scanme.nmap.org"]:
        if host in services:
            for port, info in services[host].items():
                ground_truth.append({
                    "host": host,
                    "port": int(port),
                    "state": info.get("state"),
                    "service": info.get("service"),
                    "product": info.get("product"),
                    "version": info.get("version"),
                })
    
    print(f"Loaded {len(ground_truth)} ground truth entries")
    for gt in ground_truth:
        print(f"  {gt['host']}:{gt['port']} -> {gt['service']}")
    
    # Import detector
    from cybersec.core.scanner.analysis.service_detect import ServiceDetector
    
    async def detect_service(host: str, port: int) -> Dict[str, Any]:
        """Wrapper for detector."""
        detector = ServiceDetector()
        result = await detector.detect(host, port, timeout=3.0)
        return {
            "state": result.state.value if hasattr(result.state, 'value') else str(result.state),
            "name": result.name,
            "product": result.version,  # Note: product not in ServiceInfo, using version as proxy
            "version": result.version,
        }
    
    # Run evaluation
    evaluator = ServiceDetectionEvaluator()
    results = await evaluator.evaluate(ground_truth[:2], detect_service)  # Test with 2
    
    # Print summary
    evaluator.print_summary(results)
    
    return results


if __name__ == "__main__":
    asyncio.run(run_evaluation())
