"""
tests/compare_nmap_vs_ours.py

Comparative analysis test: CyberSec Port Scanner vs Nmap.

This script:
1. Runs our AsyncPortScanner against scanme.nmap.org (Nmap's official test host)
2. Runs nmap via subprocess with matching parameters
3. Compares results: ports found, services, versions
4. Outputs a side-by-side JSON diff

Safe target: scanme.nmap.org (explicitly allowed for scanning)
Expected open ports: 22 (SSH), 80 (HTTP), 9929, 31337

Usage:
    python tests/compare_nmap_vs_ours.py
    python tests/compare_nmap_vs_ours.py --nmap-opts "-sS -T4 -F"

Note: nmap is optional. If not installed, script uses known expected results
for scanme.nmap.org and produces a comparison with our scanner only.
"""
import asyncio
import json
import subprocess
import sys
import argparse
import dataclasses
from datetime import datetime
from typing import Optional

# ─── Configuration ────────────────────────────────────────────────────────────

TARGET = "scanme.nmap.org"
TIMEOUT = 30.0  # seconds

# Known open ports on scanme.nmap.org (as of 2024)
# Source: https://scanme.nmap.org/
EXPECTED_OPEN_PORTS = {
    22: {"service": "ssh", "protocol": "tcp"},
    80: {"service": "http", "protocol": "tcp"},
    9929: {"service": "nping-echo", "protocol": "tcp"},
    31337: {"service": "Elsasoft", "protocol": "tcp"},
}

# ─── Our Scanner ───────────────────────────────────────────────────────────────

async def run_our_scanner(target: str, port_range: str = "common", retries: int = 0) -> dict:
    """Run our AsyncPortScanner against the target."""
    from cybersec.core.scanner import AsyncPortScanner

    scanner = AsyncPortScanner(timeout=3.0, retries=retries)
    report = await scanner.scan(target, port_range=port_range)

    results = []
    for port_result in report.open_ports:
        results.append({
            "port": port_result.port,
            "protocol": port_result.protocol,
            "state": port_result.state,
            "service": port_result.service.name if port_result.service else None,
            "version": port_result.service.version if port_result.service else None,
            "banner": port_result.banner,
            "risk_level": port_result.risk.risk_level if port_result.risk else None,
            "cves": [c.id for c in (port_result.cves or [])],
        })

    return {
        "target": report.target,
        "ip": report.ip,
        "scanner": "cybersec",
        "version": "1.0.0",
        "scan_mode": report.scan_mode,
        "scan_duration_seconds": round(report.scan_duration, 2),
        "total_ports_scanned": report.total_ports_scanned,
        "open_ports_count": len(results),
        "avg_latency_ms": report.avg_latency_ms,
        "peak_concurrency": report.peak_concurrency,
        "results": results,
        "completed_at": datetime.utcnow().isoformat(),
    }


# ─── Nmap Integration ─────────────────────────────────────────────────────────

def run_nmap_scan(target: str, extra_opts: str = "") -> Optional[dict]:
    """Run nmap against the target and parse XML output.

    Returns None if nmap is not installed.
    """
    cmd = [
        "nmap",
        "-oX", "-",          # XML output to stdout
        "-p", "21,22,23,25,53,80,110,143,443,445,3306,3389,5432,6379,8080,8443,9929,31337",
        "-sV",                # Service version detection
        "-T4",               # Timing: aggressive (balances speed/accuracy)
        "--reason",           # Show reason for port state
    ]

    if extra_opts:
        cmd += extra_opts.split()

    cmd.append(target)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
        )
    except FileNotFoundError:
        return None
    except subprocess.TimeoutExpired:
        return {"error": "nmap timed out", "target": target}
    except Exception as e:
        return {"error": str(e), "target": target}

    if result.returncode != 0 and "0 hosts up" not in result.stderr:
        return {"error": result.stderr or result.stdout, "target": target}

    return _parse_nmap_xml(result.stdout)


def _parse_nmap_xml(xml_output: str) -> dict:
    """Parse Nmap XML output into a dict."""
    import xml.etree.ElementTree as ET

    results = []
    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError:
        return {"error": "Failed to parse XML", "results": []}

    run_stats = root.find(".//runstats")
    finished = run_stats.find("finished") if run_stats is not None else None

    for host in root.findall(".//host"):
        addresses = host.findall("address")
        ip = next((a.get("addr") for a in addresses if a.get("addrtype") == "ipv4"), "unknown")

        for port in host.findall(".//port"):
            port_id = int(port.get("portid"))
            protocol = port.get("protocol", "tcp")
            state_el = port.find("state")
            state = state_el.get("state", "unknown") if state_el is not None else "unknown"

            service_el = port.find("service")
            service_name = service_el.get("name") if service_el is not None else None
            service_version = service_el.get("version") if service_el is not None else None
            service_product = service_el.get("product") if service_el is not None else None

            reason_el = state_el.get("reason") if state_el is not None else None

            results.append({
                "port": port_id,
                "protocol": protocol,
                "state": state,
                "service": service_name,
                "version": service_version,
                "product": service_product,
                "reason": reason_el,
            })

    elapsed = None
    if finished is not None:
        elapsed = float(finished.get("elapsed", 0))

    return {
        "target": TARGET,
        "ip": ip,
        "scanner": "nmap",
        "version": "unknown",
        "scan_mode": "nmap-default",
        "scan_duration_seconds": elapsed,
        "total_ports_scanned": len(results),
        "open_ports_count": sum(1 for r in results if r["state"] == "open"),
        "avg_latency_ms": None,
        "peak_concurrency": None,
        "results": results,
        "completed_at": datetime.utcnow().isoformat(),
    }


# ─── Comparison Engine ────────────────────────────────────────────────────────

def service_accuracy(gt: dict, pred: dict) -> float:
    """Compute service name accuracy for open ports only."""
    correct = total = 0
    for port in gt:
        if gt[port].get("state") == "open":
            total += 1
            if (gt[port].get("service") or "").lower() == (pred.get(port, {}).get("service") or "").lower():
                correct += 1
    return correct / (total + 1e-9)


def version_accuracy(gt: dict, pred: dict) -> float:
    """Compute version match accuracy (prefix matching)."""
    correct = total = 0
    for port in gt:
        if gt[port].get("state") == "open":
            gt_ver = gt[port].get("version")
            pred_ver = pred.get(port, {}).get("version")
            if gt_ver and pred_ver:
                total += 1
                if str(pred_ver).startswith(str(gt_ver)):
                    correct += 1
    return correct / (total + 1e-9)


def product_accuracy(gt: dict, pred: dict) -> float:
    """Compute product name accuracy for open ports only."""
    correct = total = 0
    for port in gt:
        if gt[port].get("state") == "open":
            total += 1
            if (gt[port].get("product") or "").lower() == (pred.get(port, {}).get("product") or "").lower():
                correct += 1
    return correct / (total + 1e-9)


def compare_results(ours: dict, nmap: Optional[dict]) -> dict:
    """Compare our scanner results against nmap (or expected results)."""

    def port_key(r: dict) -> tuple:
        return (r["port"], r.get("protocol", "tcp"))

    our_ports = {port_key(r): r for r in ours.get("results", [])}
    nmap_ports = {}
    if nmap and "error" not in nmap:
        nmap_ports = {port_key(r): r for r in nmap.get("results", [])}

    all_ports = set(our_ports.keys()) | set(nmap_ports.keys())

    matches = []
    our_misses = []  # We found it, nmap didn't (false positive?)
    nmap_misses = []  # Nmap found it, we didn't (false negative)
    both_open = []
    both_closed = []

    for port_key_ in all_ports:
        our = our_ports.get(port_key_)
        nmap_r = nmap_ports.get(port_key_)

        if our and nmap_r:
            match = {
                "port": port_key_[0],
                "protocol": port_key_[1],
                "our_state": our["state"],
                "nmap_state": nmap_r["state"],
                "our_service": our.get("service"),
                "nmap_service": nmap_r.get("service"),
                "our_version": our.get("version"),
                "nmap_version": nmap_r.get("version"),
                "states_match": our["state"] == nmap_r["state"],
                "services_match": (our.get("service") or "").lower() == (nmap_r.get("service") or "").lower(),
            }
            matches.append(match)
            if our["state"] == "open" and nmap_r["state"] == "open":
                both_open.append(port_key_[0])
            elif our["state"] in ("closed", "filtered") and nmap_r["state"] in ("closed", "filtered"):
                both_closed.append(port_key_[0])

        elif our and not nmap_r:
            our_misses.append({
                "port": port_key_[0],
                "protocol": port_key_[1],
                "our_state": our["state"],
                "our_service": our.get("service"),
            })

        elif nmap_r and not our:
            nmap_misses.append({
                "port": port_key_[0],
                "protocol": port_key_[1],
                "nmap_state": nmap_r["state"],
                "nmap_service": nmap_r.get("service"),
                "nmap_version": nmap_r.get("version"),
            })

    # Build dicts for metric functions
    gt_dict = {}
    pred_dict = {}
    for m in matches:
        gt_dict[m["port"]] = {
            "state": m["nmap_state"],
            "service": m["nmap_service"],
            "product": m.get("nmap_product"),
            "version": m.get("nmap_version"),
        }
        pred_dict[m["port"]] = {
            "state": m["our_state"],
            "service": m["our_service"],
            "product": m.get("our_product"),
            "version": m["our_version"],
        }

    total_compared = len(matches)
    svc_acc = round(service_accuracy(gt_dict, pred_dict) * 100, 1)
    ver_acc = round(version_accuracy(gt_dict, pred_dict) * 100, 1)
    prod_acc = round(product_accuracy(gt_dict, pred_dict) * 100, 1)

    # State accuracy - count matches where both agree on state
    state_matches = sum(1 for m in matches if m["states_match"])
    state_acc = round(state_matches / total_compared * 100, 1) if total_compared > 0 else 0

    return {
        "metadata": {
            "target": TARGET,
            "scanned_at": datetime.utcnow().isoformat(),
            "nmap_available": nmap is not None and "error" not in nmap,
        },
        "our_scanner": {
            "name": "CyberSec AsyncPortScanner",
            "version": "1.0.0",
            "scan_duration_seconds": ours.get("scan_duration_seconds"),
            "total_ports_scanned": ours.get("total_ports_scanned"),
            "open_ports_found": ours.get("open_ports_count"),
            "avg_latency_ms": ours.get("avg_latency_ms"),
            "peak_concurrency": ours.get("peak_concurrency"),
        },
        "nmap_scanner": None if nmap is None else {
            "name": "Nmap",
            "version": nmap.get("version", "unknown"),
            "scan_duration_seconds": nmap.get("scan_duration_seconds"),
            "total_ports_scanned": nmap.get("total_ports_scanned"),
            "open_ports_found": nmap.get("open_ports_count"),
        },
        "accuracy": {
            "total_ports_compared": total_compared,
            "state_accuracy_pct": state_acc,
            "service_accuracy_pct": svc_acc,
            "product_accuracy_pct": prod_acc,
            "version_accuracy_pct": ver_acc,
            "ports_matched": len(matches),
            "our_false_positives": len(our_misses),
            "our_false_negatives": len(nmap_misses),
            "both_found_open": both_open,
        },
        "matches": matches,
        "our_extras": our_misses,
        "nmap_extras": nmap_misses,
    }


# ─── Main ────────────────────────────────────────────────────────────────────

async def main():
    parser = argparse.ArgumentParser(description="Compare CyberSec scanner vs Nmap")
    parser.add_argument(
        "--nmap-opts",
        default="",
        help="Extra nmap options (e.g. '-sS -T4 -F')",
    )
    parser.add_argument(
        "--port-range",
        default="common",
        help="Port range for our scanner (default: common)",
    )
    parser.add_argument(
        "--skip-nmap",
        action="store_true",
        help="Skip nmap scan (use expected results only)",
    )
    parser.add_argument(
        "--output",
        default="json",
        choices=["json", "summary", "table"],
        help="Output format",
    )
    args = parser.parse_args()

    print(f"\n{'='*60}")
    print(f"  CyberSec vs Nmap — Comparative Analysis")
    print(f"  Target: {TARGET}")
    print(f"{'='*60}\n")

    # ── 1. Our Scanner ──────────────────────────────────────────────────
    print("[1/3] Running CyberSec AsyncPortScanner...")
    try:
        our_results = await run_our_scanner(TARGET, port_range=args.port_range)
        print(f"  ✓ Found {our_results['open_ports_count']} open ports in {our_results['scan_duration_seconds']}s")
        print(f"  ✓ Scanned {our_results['total_ports_scanned']} ports (peak concurrency: {our_results['peak_concurrency']})")
        for r in our_results["results"]:
            print(f"    - Port {r['port']}: {r['state']} ({r['service'] or 'unknown'})")
    except Exception as e:
        print(f"  ✗ Our scanner failed: {e}")
        our_results = {"error": str(e), "results": []}
        return

    # ── 2. Nmap Scan ───────────────────────────────────────────────────
    print("\n[2/3] Running Nmap...")
    if args.skip_nmap:
        print("  ⊘ Skipped (--skip-nmap flag set)")
        nmap_results = None
    else:
        try:
            nmap_results = run_nmap_scan(TARGET, extra_opts=args.nmap_opts)
            if nmap_results is None:
                print("  ⊘ nmap not installed — using known expected results")
                nmap_results = {
                    "error": "nmap not available",
                    "results": [
                        {"port": p, "protocol": info["protocol"], "state": "open",
                         "service": info["service"], "version": None}
                        for p, info in EXPECTED_OPEN_PORTS.items()
                    ],
                }
            elif "error" in nmap_results:
                print(f"  ⊘ nmap error: {nmap_results['error']}")
                nmap_results = None
            else:
                print(f"  ✓ Found {nmap_results['open_ports_count']} open ports in {nmap_results.get('scan_duration_seconds', '?')}s")
                for r in nmap_results["results"]:
                    if r["state"] == "open":
                        print(f"    - Port {r['port']}: {r['state']} ({r.get('service') or 'unknown'})")
        except Exception as e:
            print(f"  ⊘ nmap scan failed: {e}")
            nmap_results = None

    # ── 3. Comparison ──────────────────────────────────────────────────
    print("\n[3/3] Comparing results...")
    comparison = compare_results(our_results, nmap_results)

    # ── Output ─────────────────────────────────────────────────────────
    if args.output == "json":
        output = {
            "comparison": comparison,
            "our_results": our_results,
            "nmap_results": nmap_results,
        }
        print(json.dumps(output, indent=2, default=str))
    elif args.output == "summary":
        _print_summary(comparison, our_results, nmap_results)
    else:
        _print_table(comparison, our_results, nmap_results)

    return comparison


def _print_summary(comp: dict, ours: dict, nmap_res: Optional[dict]):
    acc = comp["accuracy"]
    print(f"\n{'─'*60}")
    print("  ACCURACY SUMMARY")
    print(f"{'─'*60}")
    print(f"  State Detection Accuracy : {acc['state_accuracy_pct']}%")
    print(f"  Service Match Accuracy  : {acc['service_accuracy_pct']}%")
    print(f"  Product Match Accuracy  : {acc['product_accuracy_pct']}%")
    print(f"  Version Match Accuracy  : {acc['version_accuracy_pct']}%")
    print(f"  Ports Compared         : {acc['total_ports_compared']}")
    print(f"  Our False Positives    : {acc['our_false_positives']}")
    print(f"  Our False Negatives    : {acc['our_false_negatives']}")
    print(f"  Both Found Open        : {acc['both_found_open']}")

    print(f"\n{'─'*60}")
    print("  PERFORMANCE")
    print(f"{'─'*60}")
    our_meta = comp["our_scanner"]
    print(f"  Our Scanner:")
    print(f"    Scan Duration  : {our_meta['scan_duration_seconds']}s")
    print(f"  Ports Scanned   : {our_meta['total_ports_scanned']}")
    print(f"  Peak Concurrency: {our_meta['peak_concurrency']}")
    if comp.get("nmap_scanner"):
        nmap_meta = comp["nmap_scanner"]
        print(f"  Nmap:")
        print(f"    Scan Duration  : {nmap_meta['scan_duration_seconds']}s")
    print(f"{'─'*60}\n")


def _print_table(comp: dict, ours: dict, nmap_res: Optional[dict]):
    print(f"\n{'═'*80}")
    print(f"  {'Port':<6} {'State':<12} {'Our Service':<16} {'Nmap Service':<16} {'Match'}")
    print(f"{'═'*80}")

    for m in comp["matches"]:
        match_icon = "✓" if m["states_match"] else "✗"
        print(
            f"  {m['port']:<6} "
            f"{m['our_state']:<12} "
            f"{str(m.get('our_service') or '-'):<16} "
            f"{str(m.get('nmap_service') or '-'):<16} "
            f"{match_icon}"
        )

    if comp["our_extras"]:
        print(f"\n{'─'*80}")
        print(f"  OUR SCANNER — Extra Findings (Nmap didn't detect)")
        for e in comp["our_extras"]:
            print(f"    Port {e['port']}: {e['our_state']} ({e.get('our_service')})")

    if comp["nmap_extras"]:
        print(f"\n{'─'*80}")
        print(f"  NMAP — Missed by Our Scanner (False Negatives)")
        for e in comp["nmap_extras"]:
            print(f"    Port {e['port']}: {e['nmap_state']} ({e.get('nmap_service')})")

    acc = comp["accuracy"]
    print(f"\n{'─'*80}")
    print(f"  Accuracy Summary:")
    print(f"    State Detection : {acc['state_accuracy_pct']}%")
    print(f"    Service Match  : {acc['service_accuracy_pct']}%")
    print(f"    Product Match  : {acc['product_accuracy_pct']}%")
    print(f"    Version Match  : {acc['version_accuracy_pct']}%\n")


if __name__ == "__main__":
    result = asyncio.run(main())
