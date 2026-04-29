import os
import json
import docker
import asyncio
from typing import Dict, Any, List

from cybersec.benchmark.runners.your_scanner_runner import CyberSecRunner
from cybersec.benchmark.runners.nmap_runner import NmapRunner
from cybersec.benchmark.runners.masscan_runner import MasscanRunner
from cybersec.benchmark.metrics.evaluator import Evaluator
from cybersec.benchmark.reporting.charts import ChartGenerator
from cybersec.benchmark.reporting.report_generator import ReportGenerator

class BenchmarkOrchestrator:
    def __init__(self, iterations=5):
        self.iterations = iterations
        self.client = docker.from_env()
        self.compose_file = os.path.join(os.path.dirname(__file__), "../lab/docker-compose.yml")
        
        ground_truth_path = os.path.join(os.path.dirname(__file__), "../../../benchmark/ground_truth/services.json")
        with open(ground_truth_path, "r") as f:
            self.ground_truth = json.load(f)
            
        self.evaluator = Evaluator(self.ground_truth)
        self.scanners = [
            CyberSecRunner(),
            NmapRunner(),
            MasscanRunner()
        ]
        self.ports_to_scan = [22, 80, 443, 3306, 5432, 6379, 8000, 8888, 8889, 9999]
    
    def setup_lab(self):
        print("Starting Docker Lab...")
        os.system(f"docker compose -f {self.compose_file} up -d")
    
    def teardown_lab(self):
        print("Tearing down Docker Lab...")
        os.system(f"docker compose -f {self.compose_file} down -v")

    def _get_target_ips(self) -> Dict[str, str]:
        targets = {"127.0.0.1": "127.0.0.1"}
        for name in self.ground_truth.keys():
            if name == "127.0.0.1": continue
            if name == "scanme.nmap.org":
                targets[name] = "scanme.nmap.org"
                continue
            try:
                container = self.client.containers.get(name)
                ip = list(container.attrs['NetworkSettings']['Networks'].values())[0]['IPAddress']
                targets[name] = ip
            except Exception as e:
                print(f"Failed to find IP for {name}: {e}")
        return targets

    async def run(self):
        self.setup_lab()
        print("Waiting 5 seconds for services to boot...")
        await asyncio.sleep(5)
        
        target_map = self._get_target_ips()
        print(f"Targets mapped: {target_map}")
        
        container_results = {s.name: {} for s in self.scanners}
        
        for iteration in range(self.iterations):
            print(f"\n--- Iteration {iteration+1}/{self.iterations} ---")
            for scanner in self.scanners:
                for target_name, target_ip in target_map.items():
                    print(f"  [{scanner.name}] Scanning {target_name} ({target_ip})...")
                    res = await scanner.scan(target_ip, self.ports_to_scan)
                    
                    if res["error"]:
                        print(f"    Error: {res['error']}")
                    else:
                        container_eval = self.evaluator.evaluate_container(target_name, res["results"])
                        if target_name not in container_results[scanner.name]:
                            container_results[scanner.name][target_name] = container_eval
                        else:
                            for level in ["service", "product", "version"]:
                                pass

        self.teardown_lab()
        
        self._print_per_container_results(container_results)

    def _print_per_container_results(self, container_results: Dict[str, Dict[str, Dict[str, float]]]):
        print("\n" + "=" * 70)
        print("PER-CONTAINER RESULTS")
        print("=" * 70)
        
        container_names = ["docker_nginx", "docker_redis", "docker_postgres", "docker_api", "docker_tarpit", "docker_filtered"]
        
        for scanner_name, results in container_results.items():
            print(f"\n{'='*70}")
            print(f"Scanner: {scanner_name}")
            print(f"{'='*70}")
            print(f"{'Container':<20} {'Service F1':<12} {'Product F1':<12} {'Version F1':<12}")
            print("-" * 60)
            
            for container in container_names:
                if container in results:
                    r = results[container]
                    print(f"{container:<20} {r['service']:<12.3f} {r['product']:<12.3f} {r['version']:<12.3f}")
                else:
                    print(f"{container:<20} {'N/A':<12} {'N/A':<12} {'N/A':<12}")