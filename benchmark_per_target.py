"""
benchmark_per_target.py - CyberSec Port Scanner Benchmarking Script

This script evaluates the accuracy of the CyberSec port scanner against a set of
Docker lab targets with known ground truth states. It compares CyberSec's output
against the industry standard Nmap, computing Precision, Recall, and F1 scores.

Usage:
  python benchmark_per_target.py [--base-url URL] [--token TOKEN] [--targets-config FILE]
"""

import json
import argparse
import time
import subprocess
import xml.etree.ElementTree as ET
import requests
import socket
from sklearn.metrics import precision_recall_fscore_support

DEFAULT_TARGETS = {
    "docker_nginx": {
        "host": "docker_nginx",
        "ground_truth": {"80": "open", "443": "open", "22": "closed", "8080": "filtered"}
    },
    "docker_redis": {
        "host": "docker_redis",
        "ground_truth": {"6379": "open", "80": "closed", "443": "filtered"}
    },
    "docker_postgres": {
        "host": "docker_postgres",
        "ground_truth": {"5432": "open", "80": "closed", "443": "filtered"}
    },
    "docker_api": {
        "host": "docker_api",
        "ground_truth": {"3000": "open", "8000": "open", "22": "closed", "80": "filtered"}
    },
    "docker_tarpit": {
        "host": "docker_tarpit",
        "ground_truth": {"9999": "open", "80": "filtered", "443": "filtered"}
    },
    "docker_filtered": {
        "host": "docker_filtered",
        "ground_truth": {"80": "filtered", "443": "filtered", "22": "filtered", "8080": "filtered"}
    }
}

def is_resolvable(hostname):
    try:
        socket.gethostbyname(hostname)
        return True
    except socket.error:
        return False

def run_nmap(target_host, ports):
    port_str = ",".join(map(str, ports))
    cmd = ["nmap", "-sT", "-p", port_str, "--open", "-oX", "-", target_host]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        
        # Nmap might return non-zero if target seems down but still produce XML
        if not result.stdout.strip().startswith("<?xml"):
            print(f"  [!] Nmap error: {result.stderr.strip()}")
            return None
        
        root = ET.fromstring(result.stdout)
        
        # Determine a default state based on <extraports> if it exists
        extra_state = "closed"
        for host in root.findall('host'):
            for ports_node in host.findall('ports'):
                extra = ports_node.find('extraports')
                if extra is not None:
                    extra_state = extra.get('state', 'closed')
        
        nmap_states = {str(p): extra_state for p in ports}
        
        for host in root.findall('host'):
            for ports_node in host.findall('ports'):
                for port in ports_node.findall('port'):
                    portid = port.get('portid')
                    state_node = port.find('state')
                    if state_node is not None:
                        nmap_states[str(portid)] = state_node.get('state')
                        
        return nmap_states
    except Exception as e:
        print(f"  [!] Failed to run Nmap: {e}")
        return None

def run_cybersec(target_host, ports, base_url, token, timeout_sec=120):
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    
    scan_req = {
        "target": target_host,
        "port_range": ",".join(map(str, ports)),
        "scan_type": "connect"
    }
    
    try:
        resp = requests.post(f"{base_url}/api/scans/", json=scan_req, headers=headers, timeout=10)
        resp.raise_for_status()
        
        data = resp.json()
        scan_id = data.get("scan_id") or data.get("id")
        if not scan_id:
            print("  [!] Could not find scan_id in CyberSec response.")
            return None
            
        # Poll for completion
        max_iters = max(1, int(timeout_sec / 2))
        for _ in range(max_iters):
            time.sleep(2)
            status_resp = requests.get(f"{base_url}/api/scans/{scan_id}/status", headers=headers, timeout=10)
            status_resp.raise_for_status()
            status = status_resp.json().get("status")
            if status == "completed":
                break
        else:
            print(f"  [!] CyberSec scan timed out after {timeout_sec}s.")
            return None
            
        # Get results
        results_resp = requests.get(f"{base_url}/api/scans/{scan_id}?format=json", headers=headers, timeout=10)
        results_resp.raise_for_status()
        res_data = results_resp.json()
        
        # Parse output
        mapped_results = {}
        valid_states = {"open", "closed", "filtered"}
        
        items = res_data.get("results", [])
        if not items and isinstance(res_data, list):
            items = res_data
        elif not items and "ports" in res_data:
            items = res_data["ports"]
            
        for item in items:
            port = str(item.get("port"))
            state = str(item.get("state", "unknown")).lower()
            if state not in valid_states:
                print(f"  [!] WARNING: Unrecognized CyberSec state '{state}' for port {port}. Defaulting to 'closed'.")
                state = "closed"
            mapped_results[port] = state
            
        # Default missing ports to closed
        for p in ports:
            if str(p) not in mapped_results:
                mapped_results[str(p)] = "closed"
                
        return mapped_results
        
    except requests.exceptions.RequestException as e:
        print(f"  [!] CyberSec API error: {e}")
        return None

def compute_metrics(y_true, y_pred):
    labels = ["open", "closed", "filtered"]
    p, r, f, _ = precision_recall_fscore_support(y_true, y_pred, labels=labels, zero_division=0)
    macro_p, macro_r, macro_f, _ = precision_recall_fscore_support(y_true, y_pred, labels=labels, average="macro", zero_division=0)
    
    class_metrics = {}
    for i, label in enumerate(labels):
        class_metrics[label] = {
            "precision": float(p[i]),
            "recall": float(r[i]),
            "f1": float(f[i])
        }
    
    return {
        "class_metrics": class_metrics,
        "macro": {
            "precision": float(macro_p),
            "recall": float(macro_r),
            "f1": float(macro_f)
        }
    }

def main():
    parser = argparse.ArgumentParser(description="Benchmark CyberSec against Nmap")
    parser.add_argument("--base-url", default="http://localhost:8000", help="Base URL for CyberSec API")
    parser.add_argument("--token", default="", help="JWT token for CyberSec API")
    parser.add_argument("--targets-config", help="JSON file with ground truth config overrides")
    parser.add_argument("--timeout", type=int, default=120, help="Timeout in seconds for CyberSec scan completion")
    args = parser.parse_args()
    
    print("\n" + "!" * 60)
    print("!!! VERIFY GROUND TRUTH BEFORE RECORDING RESULTS !!!")
    print("!" * 60 + "\n")
    
    targets = DEFAULT_TARGETS
    if args.targets_config:
        try:
            with open(args.targets_config, 'r') as f:
                targets = json.load(f)
            print(f"Loaded custom targets configuration from {args.targets_config}")
        except Exception as e:
            print(f"Error loading {args.targets_config}: {e}")
            return
            
    all_results = {}
    summary_data = []
    
    for target_name, config in targets.items():
        target_host = config.get("host", target_name)
        ground_truth = config.get("ground_truth", {})
        ports = list(ground_truth.keys())
        
        print(f"═══════════════════════════════════════")
        print(f"Target: {target_name}  ({target_host})")
        print(f"═══════════════════════════════════════")
        
        if not is_resolvable(target_host):
            print(f"  [!] Target {target_host} is unreachable/unresolvable. Skipping.")
            continue
            
        print(f"  Running CyberSec scan...")
        cs_states = run_cybersec(target_host, ports, args.base_url, args.token, args.timeout)
        if cs_states is None:
            print(f"  [!] Skipping target {target_name} due to CyberSec failure.")
            continue
            
        print(f"  Running Nmap baseline...")
        nm_states = run_nmap(target_host, ports)
        if nm_states is None:
            print(f"  [!] Skipping target {target_name} due to Nmap failure.")
            continue
            
        # Compile lists for metric calculation
        y_true = [ground_truth[str(p)] for p in ports]
        y_cs = [cs_states[str(p)] for p in ports]
        y_nm = [nm_states[str(p)] for p in ports]
        
        cs_metrics = compute_metrics(y_true, y_cs)
        nm_metrics = compute_metrics(y_true, y_nm)
        
        # Display Per-port breakdown
        print(f"\nPort  Expected   CyberSec   Nmap")
        print(f"──────────────────────────────────────")
        port_results = {}
        for p in ports:
            p_str = str(p)
            exp = ground_truth[p_str]
            cs = cs_states[p_str]
            nm = nm_states[p_str]
            
            cs_mark = "✓" if cs == exp else "✗"
            nm_mark = "✓" if nm == exp else "✗"
            
            port_results[p_str] = {
                "expected": exp,
                "cybersec": cs,
                "cybersec_correct": cs == exp,
                "nmap": nm,
                "nmap_correct": nm == exp
            }
            
            print(f"{p_str:<5} {exp:<10} {cs:<8} {cs_mark:<2} {nm:<8} {nm_mark:<2}")
            
        print(f"\nCyberSec  — Precision: {cs_metrics['macro']['precision']:.3f}  Recall: {cs_metrics['macro']['recall']:.3f}  F1: {cs_metrics['macro']['f1']:.3f}")
        print(f"Nmap      — Precision: {nm_metrics['macro']['precision']:.3f}  Recall: {nm_metrics['macro']['recall']:.3f}  F1: {nm_metrics['macro']['f1']:.3f}\n")
        
        all_results[target_name] = {
            "host": target_host,
            "ports": port_results,
            "metrics": {
                "cybersec": cs_metrics,
                "nmap": nm_metrics
            }
        }
        
        summary_data.append({
            "target": target_name,
            "cs_f1": cs_metrics["macro"]["f1"],
            "nm_f1": nm_metrics["macro"]["f1"],
            "delta": cs_metrics["macro"]["f1"] - nm_metrics["macro"]["f1"],
            "y_true": y_true,
            "y_cs": y_cs,
            "y_nm": y_nm
        })
        
    # Write full JSON report
    with open("benchmark_results.json", "w") as f:
        json.dump(all_results, f, indent=2)
    print("Saved full results to benchmark_results.json\n")
    
    if not summary_data:
        print("No targets were successfully benchmarked.")
        return

    # Compute overall F1
    all_y_true = []
    all_y_cs = []
    all_y_nm = []
    for d in summary_data:
        all_y_true.extend(d["y_true"])
        all_y_cs.extend(d["y_cs"])
        all_y_nm.extend(d["y_nm"])
        
    overall_cs = compute_metrics(all_y_true, all_y_cs)
    overall_nm = compute_metrics(all_y_true, all_y_nm)
    
    overall_cs_f1 = overall_cs["macro"]["f1"]
    overall_nm_f1 = overall_nm["macro"]["f1"]
    overall_delta = overall_cs_f1 - overall_nm_f1
    
    # Print Summary Table
    print(f"Target            CyberSec F1   Nmap F1   Delta")
    print(f"─────────────────────────────────────────────────")
    for d in summary_data:
        delta_str = f"+{d['delta']:.3f}" if d['delta'] >= 0 else f"{d['delta']:.3f}"
        print(f"{d['target']:<17} {d['cs_f1']:.3f}         {d['nm_f1']:.3f}     {delta_str}")
    print(f"─────────────────────────────────────────────────")
    overall_delta_str = f"+{overall_delta:.3f}" if overall_delta >= 0 else f"{overall_delta:.3f}"
    print(f"OVERALL           {overall_cs_f1:.3f}         {overall_nm_f1:.3f}     {overall_delta_str}")

if __name__ == "__main__":
    main()
