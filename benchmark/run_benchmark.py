#!/usr/bin/env python3
"""Quick benchmark runner for per-container results."""
import asyncio
import json
import os
import sys

from cybersec.benchmark.metrics.evaluator import Evaluator
from cybersec.benchmark.runners.your_scanner_runner import CyberSecRunner
from cybersec.benchmark.runners.nmap_runner import NmapRunner


async def main():
    ground_truth_path = "benchmark/ground_truth/services.json"
    with open(ground_truth_path, "r") as f:
        ground_truth = json.load(f)
    
    evaluator = Evaluator(ground_truth)
    scanner = CyberSecRunner()
    nmap = NmapRunner()
    
    containers = ["docker_nginx", "docker_redis", "docker_postgres", "docker_api", "docker_tarpit", "docker_filtered"]
    ports_map = {
        "docker_nginx": [80],
        "docker_redis": [6379],
        "docker_postgres": [5432],
        "docker_api": [8000],
        "docker_tarpit": [9999],
        "docker_filtered": [8888, 8889],
    }
    
    docker_ips = {}
    try:
        import docker
        client = docker.from_env()
        for name in containers:
            try:
                container = client.containers.get(name)
                ip = list(container.attrs['NetworkSettings']['Networks'].values())[0]['IPAddress']
                docker_ips[name] = ip
            except Exception as e:
                print(f"Warning: Could not get IP for {name}: {e}")
    except Exception as e:
        print(f"Docker not available: {e}")
        return
    
    print("=" * 70)
    print("CYBERSEC SCANNER RESULTS")
    print("=" * 70)
    
    cybersec_results = {}
    for container in containers:
        if container not in docker_ips:
            print(f"\n{container}: NO IP - skipped")
            continue
        
        ip = docker_ips[container]
        ports = ports_map[container]
        
        print(f"\nScanning {container} at {ip}:{ports}...")
        res = await scanner.scan(ip, ports)
        
        if res["error"]:
            print(f"  Error: {res['error']}")
            print(f"  Raw results: {res.get('results', {})}")
            continue
        
        print(f"  Raw results: {json.dumps(res['results'], indent=2)}")
        eval_result = evaluator.evaluate_container(container, res["results"])
        cybersec_results[container] = eval_result
        
        print(f"  Service F1: {eval_result['service']:.3f}")
        print(f"  Product F1: {eval_result['product']:.3f}")
        print(f"  Version F1: {eval_result['version']:.3f}")
    
    print("\n" + "=" * 70)
    print("SUMMARY TABLE")
    print("=" * 70)
    print(f"{'Container':<20} {'Service F1':<12} {'Product F1':<12} {'Version F1':<12}")
    print("-" * 60)
    
    for container in containers:
        if container in cybersec_results:
            r = cybersec_results[container]
            print(f"{container:<20} {r['service']:<12.3f} {r['product']:<12.3f} {r['version']:<12.3f}")
        else:
            print(f"{container:<20} {'N/A':<12} {'N/A':<12} {'N/A':<12}")


if __name__ == "__main__":
    asyncio.run(main())