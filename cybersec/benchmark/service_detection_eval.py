"""
Service Detection Evaluation Script for Docker Lab

Measures real accuracy against ground truth with statistical rigor.
3 runs per target, reports avg/worst-case accuracy.
"""
import asyncio
import json
import sys
import os
from typing import Dict, List, Any, Tuple
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from cybersec.core.scanner.analysis.service_detect import ServiceDetector, BannerGrabber, ServiceProber, ServiceDetectorPipeline


GROUND_TRUTH_DOCKER = {
    ("127.0.0.1", 6379): "redis",
    ("127.0.0.1", 5432): "postgresql",
}

GROUND_TRUTH_INTERNET = {
    ("scanme.nmap.org", 22): "ssh",
    ("scanme.nmap.org", 80): "http",
}

ALL_GROUND_TRUTH = {**GROUND_TRUTH_DOCKER, **GROUND_TRUTH_INTERNET}

RUNS_PER_TARGET = 3


async def detect_service(host: str, port: int, detector: ServiceDetector, timeout: float = 2.5) -> Dict[str, Any]:
    """Run detection on a single port."""
    try:
        result = await detector.detect(host, port, timeout=timeout)
        return {
            "host": host,
            "port": port,
            "detected": result.name,
            "confidence": result.confidence,
            "banner": result.banner[:100] if result.banner else None,
            "error": None,
        }
    except Exception as e:
        return {
            "host": host,
            "port": port,
            "detected": "error",
            "confidence": 0,
            "banner": None,
            "error": str(e),
        }


async def run_evaluation(runs: int = RUNS_PER_TARGET) -> Dict[str, Any]:
    """Run full evaluation with multiple runs."""
    detector = ServiceDetector()
    results = defaultdict(lambda: {"matches": [], "confidences": [], "detected": []})
    
    print("=" * 60)
    print("SERVICE DETECTION EVALUATION")
    print(f"Ground truth targets: {len(ALL_GROUND_TRUTH)}")
    print(f"Runs per target: {runs}")
    print("=" * 60)
    
    # Run detection runs times per target
    for run in range(runs):
        print(f"\n--- Run {run + 1}/{runs} ---")
        
        for (host, port), expected in ALL_GROUND_TRUTH.items():
            result = await detect_service(host, port, detector)
            
            match = result["detected"].lower() == expected.lower()
            results[(host, port)]["matches"].append(match)
            results[(host, port)]["confidences"].append(result["confidence"])
            results[(host, port)]["detected"].append(result["detected"])
            results[(host, port)]["expected"] = expected
            
            status = "✓" if match else "✗"
            print(f"  {host}:{port} ({expected}) -> {result['detected']} conf={result['confidence']} {status}")
            
            await asyncio.sleep(0.1)
    
    # Aggregate results
    print("\n" + "=" * 60)
    print("PER-TARGET RESULTS")
    print("=" * 60)
    
    per_service = defaultdict(lambda: {"matches": [], "confidences": []})
    
    for (host, port), data in results.items():
        expected = data["expected"]
        matches = data["matches"]
        confidences = data["confidences"]
        detected = data["detected"]
        
        # Per-service aggregation
        per_service[expected]["matches"].extend(matches)
        per_service[expected]["confidences"].extend(confidences)
        
        # Target stats
        accuracy = sum(matches) / len(matches) * 100
        avg_conf = sum(confidences) / len(confidences)
        min_conf = min(confidences)
        
        print(f"{host}:{port} ({expected}):")
        print(f"  Detection: {detected[0]} (consistent: {len(set(detected)) == 1})")
        print(f"  Accuracy: {accuracy:.1f}%")
        print(f"  Confidence: avg={avg_conf:.1f}, min={min_conf}")
    
    # Per-service stats
    print("\n" + "=" * 60)
    print("PER-SERVICE ACCURACY")
    print("=" * 60)
    
    service_metrics = {}
    for service, data in per_service.items():
        matches = data["matches"]
        confidences = data["confidences"]
        
        acc = sum(matches) / len(matches) * 100
        avg_conf = sum(confidences) / len(confidences)
        min_conf = min(confidences)
        
        service_metrics[service] = {
            "accuracy": acc,
            "avg_confidence": avg_conf,
            "min_confidence": min_conf,
            "runs": len(matches),
        }
        
        print(f"{service}:")
        print(f"  Accuracy: {acc:.1f}%")
        print(f"  Confidence: avg={avg_conf:.1f}, min={min_conf}")
    
    # Overall stats
    all_matches = []
    all_confidences = []
    for data in results.values():
        all_matches.extend(data["matches"])
        all_confidences.extend(data["confidences"])
    
    overall_accuracy = sum(all_matches) / len(all_matches) * 100
    avg_confidence = sum(all_confidences) / len(all_confidences)
    min_confidence = min(all_confidences)
    
    # Non-standard port test (ports != standard)
    nonstd_ports = {6379, 5432, 8080, 8000, 8888}
    std_ports = {22, 80, 443}
    
    nonstd = [(k, v) for k, v in results.items() if k[1] in nonstd_ports and k[1] not in std_ports]
    nonstd_matches = [m for data in nonstd for m in data[1]["matches"]]
    nonstd_acc = sum(nonstd_matches) / len(nonstd_matches) * 100 if nonstd_matches else 0
    
    print("\n" + "=" * 60)
    print("OVERALL RESULTS")
    print("=" * 60)
    print(f"Overall Accuracy: {overall_accuracy:.1f}%")
    print(f"Avg Confidence: {avg_confidence:.1f}%")
    print(f"Min Confidence: {min_confidence}%")
    print(f"Non-standard port accuracy: {nonstd_acc:.1f}%")
    
    # Format output
    output = {
        "overall_accuracy": round(overall_accuracy, 2),
        "overall_avg_confidence": round(avg_confidence, 2),
        "overall_min_confidence": min_confidence,
        "service_metrics": {k: {kk: round(vv, 2) for kk, vv in v.items()} for k, v in service_metrics.items()},
        "non_standard_port_accuracy": round(nonstd_acc, 2),
        "total_runs": len(all_matches),
        "targets_tested": len(results),
    }
    
    print("\n" + "=" * 60)
    print("FINAL METRICS")
    print("=" * 60)
    print("BEFORE:")
    print("overall_accuracy: 0.50")
    print()
    print("AFTER:")
    print(f"overall_accuracy: {output['overall_accuracy']:.2f}")
    print(f"http_accuracy: {service_metrics.get('http', {}).get('accuracy', 0):.2f}")
    print(f"ssh_accuracy: {service_metrics.get('ssh', {}).get('accuracy', 0):.2f}")
    print(f"redis_accuracy: {service_metrics.get('redis', {}).get('accuracy', 0):.2f}")
    print(f"postgres_accuracy: {service_metrics.get('postgresql', {}).get('accuracy', 0):.2f}")
    print(f"non_standard_port_accuracy: {output['non_standard_port_accuracy']:.2f}")
    
    return output


async def main():
    """Main entry point."""
    import argparse
    parser = argparse.ArgumentParser(description="Service detection evaluation")
    parser.add_argument("-r", "--runs", type=int, default=RUNS_PER_TARGET, help="Runs per target")
    args = parser.parse_args()
    
    results = await run_evaluation(runs=args.runs)
    
    # Save to file
    output_path = "service_detection_results.json"
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"\nResults saved to: {output_path}")
    
    return results


if __name__ == "__main__":
    asyncio.run(main())