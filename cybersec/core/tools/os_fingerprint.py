import asyncio
import dataclasses
import ipaddress
import re
import socket
import struct
import sys
import time
from asyncio import subprocess as asy_sub
from dataclasses import dataclass, field

from cybersec.core.tools.geoip import geoip_lookup
from cybersec.core.tools.port_scanner import OpenPortDetail, scan_ports


OS_FINGERPRINT_PORTS = [
    21, 22, 23, 25, 53, 80, 135, 139, 443, 445, 515, 548, 631, 9100,
    1433, 2375, 2376, 3306, 3389, 5432, 5900, 5985, 5986, 6379, 8080, 8443, 27017,
]


@dataclass
class OsFingerprintResult:
    target: str
    ip: str | None
    detected_os: str
    family: str
    os_version_estimate: str | None
    distribution_family: str | None
    kernel_estimate: str | None
    device_type: str
    environment: str
    hosting_provider: str | None
    confidence: int
    confidence_label: str
    method: str
    detection_mode: str
    virtualization_signals: list[str] = field(default_factory=list)
    os_probabilities: list[dict] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    fingerprint_sources: list[dict] = field(default_factory=list)
    tcp_ip_stack: dict = field(default_factory=dict)
    network_distance: dict = field(default_factory=dict)
    uptime_estimate: dict = field(default_factory=dict)
    service_os_correlation: list[dict] = field(default_factory=list)
    cpe_matches: list[dict] = field(default_factory=list)
    mitre_attack: list[dict] = field(default_factory=list)
    attack_surface_by_os: list[str] = field(default_factory=list)
    eol_findings: list[dict] = field(default_factory=list)
    vulnerability_correlation: list[dict] = field(default_factory=list)
    fingerprint_timeline: list[dict] = field(default_factory=list)
    hardening_indicators: list[dict] = field(default_factory=list)
    firewall_detection: dict = field(default_factory=dict)
    honeypot_detection: dict = field(default_factory=dict)
    risk_score: dict = field(default_factory=dict)
    ai_summary: str | None = None
    internet_exposure: dict = field(default_factory=dict)
    geolocation: dict = field(default_factory=dict)
    historical_comparison: dict = field(default_factory=dict)
    scan_quality: dict = field(default_factory=dict)
    ttl: int | None = None
    open_ports: list[dict] = field(default_factory=list)
    scan_duration_seconds: float = 0.0
    error: str | None = None


def _ttl_guess(ttl: int | None) -> tuple[str | None, str | None, int, str | None]:
    if ttl is None:
        return None, None, 0, None
    if ttl <= 64:
        return "Linux/Unix-like", "unix", 28, f"Observed TTL {ttl}, commonly near a Linux/Unix initial TTL of 64"
    if ttl <= 128:
        return "Windows", "windows", 30, f"Observed TTL {ttl}, commonly near a Windows initial TTL of 128"
    return "Network appliance or Unix-like", "network", 22, f"Observed TTL {ttl}, commonly near an initial TTL of 255"


def _initial_ttl(ttl: int | None) -> int | None:
    if ttl is None:
        return None
    if ttl <= 64:
        return 64
    if ttl <= 128:
        return 128
    return 255


def _confidence_label(confidence: int) -> str:
    if confidence >= 80:
        return "High"
    if confidence >= 55:
        return "Moderate"
    if confidence >= 30:
        return "Low"
    return "Insufficient"


def _banner_guess(port: OpenPortDetail) -> tuple[str | None, str | None, int, str | None]:
    haystack = " ".join(
        value for value in [port.version, port.raw_banner, port.welcome_message, port.server_response] if value
    ).lower()

    if any(token in haystack for token in ["ubuntu", "debian", "centos", "red hat", "fedora", "openssh"]):
        return "Linux/Unix-like", "unix", 24, f"Port {port.port_number} banner suggests Unix/Linux software"
    if any(token in haystack for token in ["microsoft", "iis", "winrm", "windows"]):
        return "Windows", "windows", 28, f"Port {port.port_number} banner contains Microsoft/Windows indicators"
    if any(token in haystack for token in ["darwin", "macos", "mac os"]):
        return "macOS", "macos", 28, f"Port {port.port_number} banner contains macOS indicators"

    if port.port_number in {135, 139, 445, 3389, 5985, 5986}:
        return "Windows", "windows", 22, f"Port {port.port_number} is commonly associated with Windows hosts"
    if port.port_number == 548:
        return "macOS", "macos", 20, "AFP port 548 is commonly associated with Apple/macOS hosts"
    if port.port_number == 631:
        return "Linux/Unix-like", "unix", 12, "IPP/CUPS port 631 is commonly associated with Unix-like hosts"

    return None, None, 0, None


def _service_text(port: OpenPortDetail) -> str:
    return " ".join(
        str(value)
        for value in [port.service, port.version, port.raw_banner, port.welcome_message, port.server_response]
        if value
    ).lower()


def _score_service_distribution(port: OpenPortDetail, scores: dict[str, int], correlations: list[dict]) -> None:
    text = _service_text(port)
    version = port.version or port.fingerprint.get("detected") if port.fingerprint else port.version
    service = port.service or f"TCP/{port.port_number}"

    rules = [
        ("ubuntu", "Ubuntu Linux", "Ubuntu package marker in service banner", 40),
        ("debian", "Debian Linux", "Debian package marker in service banner", 36),
        ("centos", "CentOS/RHEL family", "CentOS marker in service banner", 38),
        ("red hat", "CentOS/RHEL family", "Red Hat marker in service banner", 38),
        ("rhel", "CentOS/RHEL family", "RHEL marker in service banner", 38),
        ("fedora", "Fedora/RHEL family", "Fedora marker in service banner", 30),
        ("microsoft-iis", "Windows Server", "IIS banner strongly indicates Windows Server", 42),
        ("winrm", "Windows Server", "WinRM service indicates Windows Server", 36),
        ("openssh", "Ubuntu/Debian Linux", "OpenSSH is common on Linux server deployments", 14),
        ("apache/2.4", "Ubuntu/Debian Linux", "Apache 2.4 is common on Ubuntu/Debian web servers", 16),
        ("nginx", "Linux server", "Nginx is commonly deployed on Linux hosts", 14),
    ]
    for needle, label, reason, points in rules:
        if needle in text:
            scores[label] = scores.get(label, 0) + points
            correlations.append({
                "service": service,
                "version": version,
                "os_signal": label,
                "reason": reason,
                "confidence": min(95, points + 38),
            })


def _estimate_versions(distribution_scores: dict[str, int], open_ports: list[OpenPortDetail]) -> tuple[str | None, str | None]:
    if not distribution_scores:
        return None, None

    distro = max(distribution_scores.items(), key=lambda item: item[1])[0]
    haystack = " ".join(_service_text(port) for port in open_ports)

    if "ubuntu" in haystack:
        if "ubuntu-0ubuntu" in haystack or "ubuntu" in haystack:
            return "Ubuntu Linux 20.04-22.04 likely", "Debian-based system likely"
    if distro in {"Ubuntu/Debian Linux", "Ubuntu Linux", "Debian Linux"}:
        return "Ubuntu/Debian Linux 10-12 or Ubuntu 20.04-22.04 likely", "Debian-based system likely"
    if "CentOS" in distro or "RHEL" in distro or "Fedora" in distro:
        return "CentOS/RHEL family 7-9 likely", "RHEL-family system likely"
    if "Windows" in distro:
        return "Windows Server 2016-2022 likely", "Windows Server family"
    if "Linux" in distro:
        return "Linux distribution not uniquely identifiable", "Linux/Unix-like"
    return distro, distro


def _estimate_kernel(family: str, ttl: int | None, open_ports: list[OpenPortDetail]) -> str | None:
    text = " ".join(_service_text(port) for port in open_ports)
    if family == "windows":
        return "Windows NT kernel 10.x likely"
    if family == "macos":
        return "XNU kernel likely"
    if family in {"unix", "network"}:
        if "openssh_6." in text or "apache/2.4.7" in text:
            return "Linux 3.x-4.x likely"
        if "openssh_8." in text or "openssh_9." in text:
            return "Linux 5.x-6.x likely"
        if ttl is not None:
            return "Linux 4.x-6.x likely" if ttl <= 64 else "Unix-like kernel likely"
    return None


def _device_type(open_ports: list[OpenPortDetail], family: str, geo: dict) -> str:
    ports = {port.port_number for port in open_ports}
    org = " ".join(str(geo.get(key) or "").lower() for key in ("org", "isp", "asn_type"))
    if {9100, 515, 631} & ports:
        return "Printer"
    if {548, 445} <= ports:
        return "NAS or file server"
    if {3389, 5985, 5986} & ports:
        return "Windows server"
    if {80, 443, 8080, 8443} & ports and ("cloud" in org or "hosting" in org or geo.get("is_hosting")):
        return "Public server"
    if {53, 80, 443} <= ports and len(ports) <= 5:
        return "Router or network appliance"
    if {22, 80, 443} & ports:
        return "Server"
    if family == "network":
        return "Router or firewall"
    return "Host"


def _environment(open_ports: list[OpenPortDetail], geo: dict) -> tuple[str, list[str]]:
    text = " ".join(_service_text(port) for port in open_ports)
    org = " ".join(str(geo.get(key) or "").lower() for key in ("org", "isp", "asn", "asn_domain"))
    signals = []
    providers = {
        "VMware": ["vmware"],
        "VirtualBox": ["virtualbox"],
        "KVM": ["kvm", "qemu", "libvirt"],
        "Hyper-V": ["hyper-v", "hyperv", "microsoft"],
        "Docker/LXC": ["docker", "lxc", "container"],
    }
    for provider, needles in providers.items():
        if any(needle in text for needle in needles):
            signals.append(provider)
    if geo.get("is_hosting") or any(token in org for token in ["linode", "akamai", "amazon", "aws", "digitalocean", "azure", "google cloud", "hetzner"]):
        signals.append("Cloud-hosted virtualized environment")
    label = f"Likely Virtual Machine ({signals[0]})" if signals else "Unknown"
    return label, signals


def _cloud_provider(geo: dict) -> str | None:
    haystack = " ".join(str(geo.get(key) or "").lower() for key in ("org", "isp", "asn", "asn_domain", "rdap_name", "reverse_dns"))
    providers = {
        "Linode": ["linode", "akamai connected cloud"],
        "AWS": ["amazon", "aws", "ec2"],
        "Azure": ["azure", "microsoft"],
        "Google Cloud": ["google cloud", "google"],
        "DigitalOcean": ["digitalocean"],
        "Cloudflare": ["cloudflare"],
        "Hetzner": ["hetzner"],
        "Oracle Cloud": ["oracle"],
    }
    for provider, needles in providers.items():
        if any(needle in haystack for needle in needles):
            return provider
    return geo.get("org") or geo.get("isp")


async def _tcp_probe(target: str, ports: list[OpenPortDetail], timeout: float) -> dict:
    target_port = next((port.port_number for port in ports), None)
    base = {
        "port": target_port,
        "window_size": None,
        "mss": None,
        "sack_permitted": None,
        "timestamps_enabled": None,
        "window_scaling": None,
        "tcp_options": [],
        "raw_packet_capture": False,
        "note": "Uses local TCP_INFO when available; raw remote SYN option capture requires privileged packet probing.",
    }
    if target_port is None or not hasattr(socket, "TCP_INFO"):
        base["note"] = "TCP stack details unavailable on this platform or no open TCP port was found."
        return base

    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(target, target_port), timeout=timeout)
        sock = writer.get_extra_info("socket")
        info = sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 104)
        options = info[5] if len(info) > 5 else 0
        snd_mss = struct.unpack_from("I", info, 16)[0] if len(info) >= 20 else None
        rcv_space = struct.unpack_from("I", info, 96)[0] if len(info) >= 100 else None
        base.update({
            "window_size": rcv_space,
            "mss": snd_mss,
            "sack_permitted": bool(options & 2),
            "timestamps_enabled": bool(options & 1),
            "window_scaling": bool(options & 4),
            "tcp_options": [
                name for bit, name in [(1, "timestamps"), (2, "sack"), (4, "window_scale"), (8, "ecn_seen")]
                if options & bit
            ],
        })
        writer.close()
        await writer.wait_closed()
    except Exception as exc:
        base["note"] = f"TCP_INFO probe unavailable: {exc}"
    return base


def _cpe_matches(open_ports: list[OpenPortDetail], family: str) -> list[dict]:
    matches = []
    if family in {"unix", "network"}:
        matches.append({"type": "operating-system", "cpe": "cpe:/o:linux:linux_kernel", "confidence": 60})
    if family == "windows":
        matches.append({"type": "operating-system", "cpe": "cpe:/o:microsoft:windows_server", "confidence": 65})
    for port in open_ports:
        text = _service_text(port)
        version = port.version or ""
        if "apache" in text:
            matches.append({"type": "application", "cpe": f"cpe:/a:apache:http_server:{_extract_version(version) or '*'}", "confidence": 70})
        if "openssh" in text:
            matches.append({"type": "application", "cpe": f"cpe:/a:openbsd:openssh:{_extract_version(version) or '*'}", "confidence": 70})
        if "nginx" in text:
            matches.append({"type": "application", "cpe": f"cpe:/a:nginx:nginx:{_extract_version(version) or '*'}", "confidence": 68})
        if "microsoft-iis" in text:
            matches.append({"type": "application", "cpe": f"cpe:/a:microsoft:iis:{_extract_version(version) or '*'}", "confidence": 72})
    return matches[:10]


def _extract_version(text: str | None) -> str | None:
    if not text:
        return None
    match = re.search(r"(\d+(?:\.\d+){1,3}[a-z0-9._-]*)", text, re.IGNORECASE)
    return match.group(1) if match else None


def _eol_and_vuln_findings(open_ports: list[OpenPortDetail]) -> tuple[list[dict], list[dict]]:
    eol = []
    vulns = []
    for port in open_ports:
        text = _service_text(port)
        version = port.version or port.fingerprint.get("detected") if port.fingerprint else port.version
        if "apache/2.4.7" in text:
            eol.append({"component": "Apache HTTP Server 2.4.7", "status": "Outdated", "reason": "Apache 2.4.7 is associated with old Ubuntu-era packages."})
            vulns.append({"component": "Apache HTTP Server 2.4.7", "finding": "Potential historical CVEs; validate with authenticated/package-aware scanning.", "severity": "medium"})
        if "openssh_6." in text:
            eol.append({"component": version or "OpenSSH 6.x", "status": "Aged", "reason": "OpenSSH 6.x is an older major release."})
            vulns.append({"component": version or "OpenSSH 6.x", "finding": "Potential OpenSSH CVEs may apply depending on vendor backports.", "severity": "medium"})
        if "ubuntu 14" in text or "ubuntu 16" in text:
            eol.append({"component": version or "Ubuntu release marker", "status": "End-of-life likely", "reason": "Observed Ubuntu marker suggests an old LTS generation."})
    return eol, vulns


def _mitre(open_ports: list[OpenPortDetail]) -> list[dict]:
    techniques = [
        {"id": "T1082", "name": "System Information Discovery", "tactic": "Discovery", "reason": "OS fingerprinting identifies platform and system traits."}
    ]
    for port in open_ports:
        if port.port_number in {22, 3389, 5985, 5986, 445}:
            techniques.append({"id": "T1021", "name": "Remote Services", "tactic": "Lateral Movement", "reason": f"{port.service} is exposed on TCP/{port.port_number}."})
        if port.port_number in {80, 443, 8080, 8443}:
            techniques.append({"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access", "reason": f"Web service is exposed on TCP/{port.port_number}."})
    seen = set()
    unique = []
    for item in techniques:
        key = (item["id"], item["reason"])
        if key not in seen:
            unique.append(item)
            seen.add(key)
    return unique[:8]


def _attack_surface(family: str, open_ports: list[OpenPortDetail]) -> list[str]:
    ports = {port.port_number for port in open_ports}
    items = []
    if family in {"unix", "network"}:
        if 22 in ports:
            items.append("SSH brute force and credential stuffing exposure")
        if ports & {80, 443, 8080, 8443}:
            items.append("Public web application and web server exploit exposure")
        if ports & {3306, 5432, 6379, 27017}:
            items.append("Database service exposure requiring strict network controls")
        items.append("Package/version drift can create Linux service CVE exposure")
    elif family == "windows":
        if ports & {3389, 5985, 5986}:
            items.append("Remote administration exposure via RDP or WinRM")
        if 445 in ports:
            items.append("SMB share, relay, and lateral movement exposure")
    return items[:6]


def _hardening_and_firewall(open_ports: list[OpenPortDetail], ttl: int | None, scanned_count: int) -> tuple[list[dict], dict]:
    indicators = []
    open_count = len(open_ports)
    if ttl is None:
        indicators.append({"name": "ICMP response", "status": "limited", "detail": "ICMP TTL was not observed; ping may be filtered."})
    if open_count <= 2 and scanned_count > 10:
        indicators.append({"name": "Small exposed surface", "status": "positive", "detail": "Few fingerprinting ports responded."})
    firewall_possible = ttl is None or open_count == 0 or open_count <= 2
    firewall = {
        "possible": firewall_possible,
        "confidence": 65 if firewall_possible else 25,
        "reason": "Limited ICMP/TCP responses suggest filtering." if firewall_possible else "Multiple expected services responded consistently.",
    }
    return indicators, firewall


def _honeypot(open_ports: list[OpenPortDetail]) -> dict:
    text = " ".join(_service_text(port) for port in open_ports)
    signals = []
    if "cowrie" in text:
        signals.append("Cowrie SSH honeypot banner marker")
    if "kippo" in text:
        signals.append("Kippo SSH honeypot banner marker")
    if len(open_ports) > 12:
        signals.append("Large number of common services exposed during a small fingerprint scan")
    return {
        "possible": bool(signals),
        "confidence": 80 if signals else 15,
        "signals": signals,
        "summary": "Behavior resembles a honeypot." if signals else "No obvious honeypot indicators observed.",
    }


def _risk_score(open_ports: list[OpenPortDetail], eol: list[dict], vulns: list[dict], firewall: dict) -> dict:
    risky_ports = {22: 12, 23: 25, 445: 20, 3389: 24, 3306: 18, 5432: 18, 6379: 22, 27017: 20}
    score = 20 + sum(risky_ports.get(port.port_number, 6 if port.port_number in {80, 443, 8080, 8443} else 2) for port in open_ports)
    score += min(25, len(eol) * 10 + len(vulns) * 8)
    if firewall.get("possible"):
        score -= 8
    score = max(0, min(100, score))
    return {
        "score": score,
        "level": "critical" if score >= 80 else "high" if score >= 60 else "medium" if score >= 35 else "low",
        "drivers": [
            f"{len(open_ports)} open fingerprinting service(s)",
            f"{len(eol)} outdated/EOL indicator(s)",
            f"{len(vulns)} vulnerability correlation(s)",
        ],
    }


def _timeline(ttl: int | None, open_ports: list[OpenPortDetail], correlations: list[dict], confidence: int) -> list[dict]:
    steps = [
        {"step": "TTL Analysis", "status": "complete" if ttl is not None else "limited", "detail": f"Observed TTL {ttl}" if ttl is not None else "No ICMP TTL observed", "confidence_after": 28 if ttl is not None else 5},
        {"step": "Port Fingerprinting", "status": "complete", "detail": f"{len(open_ports)} open service(s) matched", "confidence_after": min(55, 20 + len(open_ports) * 8)},
        {"step": "Banner Analysis", "status": "complete" if correlations else "limited", "detail": f"{len(correlations)} OS/service correlation(s)", "confidence_after": min(75, 35 + len(correlations) * 10)},
        {"step": "OS Correlation", "status": "complete", "detail": "Probability engine ranked candidate OS families", "confidence_after": confidence},
        {"step": "Final Detection", "status": "complete", "detail": "Final report generated", "confidence_after": confidence},
    ]
    return steps


def _probabilities(family_scores: dict[str, int], distribution_scores: dict[str, int], ttl: int | None) -> list[dict]:
    candidates = dict(distribution_scores)
    if not candidates:
        labels = {"unix": "Linux/Unix-like", "windows": "Windows Server", "macos": "macOS", "network": "Network Appliance/Unix"}
        candidates = {labels.get(k, k): v for k, v in family_scores.items()}
    if ttl is not None and "Linux/Unix-like" not in candidates and "Ubuntu/Debian Linux" not in candidates and ttl <= 64:
        candidates["Linux/Unix-like"] = candidates.get("Linux/Unix-like", 0) + 24
    if not candidates:
        candidates = {"Unknown": 1}
    total = max(1, sum(candidates.values()))
    probabilities = [
        {"name": name, "probability": round((score / total) * 100), "score": score}
        for name, score in sorted(candidates.items(), key=lambda item: item[1], reverse=True)
    ]
    remainder = 100 - sum(item["probability"] for item in probabilities)
    if probabilities:
        probabilities[0]["probability"] += remainder
    return probabilities[:5]


async def _resolve_ipv4(target: str) -> tuple[str | None, str | None]:
    try:
        loop = asyncio.get_running_loop()
        ip = (await loop.getaddrinfo(target, None, family=socket.AF_INET, type=socket.SOCK_STREAM))[0][4][0]
        return ip, None
    except Exception as exc:
        return None, f"DNS resolution failed: {exc}"


async def _read_ttl(target: str, timeout: float) -> int | None:
    if sys.platform == "win32":
        cmd = ["ping", "-n", "1", "-w", str(max(1, int(timeout * 1000))), target]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout))), target]

    try:
        process = await asyncio.create_subprocess_exec(*cmd, stdout=asy_sub.PIPE, stderr=asy_sub.PIPE)
        stdout, _ = await asyncio.wait_for(process.communicate(), timeout=timeout + 1.0)
    except Exception:
        return None

    match = re.search(r"\bttl[=:\s]+(\d+)\b", stdout.decode("utf-8", errors="ignore"), re.IGNORECASE)
    return int(match.group(1)) if match else None


def _choose_os(scores: dict[str, int]) -> tuple[str, str, int]:
    if not scores:
        return "Unknown", "unknown", 0

    labels = {
        "windows": "Windows",
        "unix": "Linux/Unix-like",
        "macos": "macOS",
        "network": "Network appliance or Unix-like",
    }
    family, score = max(scores.items(), key=lambda item: item[1])
    return labels.get(family, "Unknown"), family, min(95, max(20, score))


async def os_fingerprint(target: str, timeout: float = 2.0) -> OsFingerprintResult:
    start = time.time()
    ip, error = await _resolve_ipv4(target)
    if error:
        return OsFingerprintResult(
            target=target,
            ip=None,
            detected_os="Unknown",
            family="unknown",
            os_version_estimate=None,
            distribution_family=None,
            kernel_estimate=None,
            device_type="Unknown",
            environment="Unknown",
            hosting_provider=None,
            confidence=0,
            confidence_label="Insufficient",
            os_probabilities=[],
            virtualization_signals=[],
            method="passive TCP/ICMP fingerprint",
            detection_mode="Passive Fingerprinting",
            scan_duration_seconds=time.time() - start,
            error=error,
        )

    ttl_task = asyncio.create_task(_read_ttl(target, timeout))
    geo_task = asyncio.create_task(geoip_lookup(target))
    ports_result = await scan_ports(target, ports=OS_FINGERPRINT_PORTS, timeout=timeout, max_concurrent=40)
    ttl = await ttl_task
    geo_result = await geo_task
    geo = dataclasses.asdict(geo_result)

    evidence: list[str] = []
    scores: dict[str, int] = {}
    distribution_scores: dict[str, int] = {}
    correlations: list[dict] = []

    _, ttl_family, ttl_score, ttl_evidence = _ttl_guess(ttl)
    if ttl_family:
        scores[ttl_family] = scores.get(ttl_family, 0) + ttl_score
    if ttl_evidence:
        evidence.append(ttl_evidence)

    for port in ports_result.open_ports:
        _, family, score, item_evidence = _banner_guess(port)
        if family:
            scores[family] = scores.get(family, 0) + score
        if item_evidence:
            evidence.append(item_evidence)
        _score_service_distribution(port, distribution_scores, correlations)

    detected_os, family, confidence = _choose_os(scores)
    probabilities = _probabilities(scores, distribution_scores, ttl)
    if probabilities and probabilities[0]["name"] != "Unknown":
        detected_os = probabilities[0]["name"]
        confidence = max(confidence, probabilities[0]["probability"])

    if confidence == 0:
        evidence.append("No OS-specific TTL, banner, or port indicators were captured")

    initial_ttl = _initial_ttl(ttl)
    hop_distance = initial_ttl - ttl if ttl is not None and initial_ttl is not None else None
    os_version, distribution_family = _estimate_versions(distribution_scores, ports_result.open_ports)
    kernel_estimate = _estimate_kernel(family, ttl, ports_result.open_ports)
    environment, virtualization_signals = _environment(ports_result.open_ports, geo)
    tcp_stack = await _tcp_probe(target, ports_result.open_ports, timeout)
    cpes = _cpe_matches(ports_result.open_ports, family)
    eol_findings, vuln_correlation = _eol_and_vuln_findings(ports_result.open_ports)
    hardening, firewall = _hardening_and_firewall(ports_result.open_ports, ttl, len(OS_FINGERPRINT_PORTS))
    honeypot = _honeypot(ports_result.open_ports)
    risk = _risk_score(ports_result.open_ports, eol_findings, vuln_correlation, firewall)
    cloud_provider = _cloud_provider(geo)
    device_type = _device_type(ports_result.open_ports, family, geo)

    source_breakdown = [
        {
            "name": "TTL Analysis",
            "status": "observed" if ttl is not None else "not observed",
            "observed_ttl": ttl,
            "estimated_initial_ttl": initial_ttl,
            "inference": ttl_evidence or "ICMP TTL unavailable",
        },
        {
            "name": "Banner Analysis",
            "status": "observed" if correlations else "limited",
            "items": correlations[:6],
        },
        {
            "name": "Port Behavior",
            "status": "observed",
            "open_ports": [port.port_number for port in ports_result.open_ports],
            "inference": "Port signatures align with the ranked OS probabilities." if ports_result.open_ports else "No fingerprinting ports responded.",
        },
        {
            "name": "TCP/IP Stack",
            "status": "observed" if tcp_stack.get("mss") else "limited",
            "details": tcp_stack,
        },
    ]

    exposure = {
        "classification": "Public Internet Facing Host" if _is_public_ip(ip) else "Private or Local Host",
        "is_public": _is_public_ip(ip),
        "open_service_count": len(ports_result.open_ports),
        "detail": "Target resolved to a public IP address." if _is_public_ip(ip) else "Target IP is private, local, or reserved.",
    }
    geolocation = {
        "country": geo.get("country"),
        "country_code": geo.get("country_code"),
        "city": geo.get("city"),
        "asn": geo.get("asn"),
        "org": geo.get("org"),
        "isp": geo.get("isp"),
        "provider": cloud_provider,
        "reverse_dns": geo.get("reverse_dns"),
    }
    quality_reasons = []
    if ttl is None:
        quality_reasons.append("TTL unavailable")
    if len(ports_result.open_ports) < 3:
        quality_reasons.append("Limited ports available for analysis")
    if not correlations:
        quality_reasons.append("No strong OS-specific banners")
    quality = {
        "label": _confidence_label(confidence),
        "score": confidence,
        "reason": "; ".join(quality_reasons) if quality_reasons else "TTL, service, and banner signals are available.",
    }
    summary_bits = [
        f"The target appears to be a {detected_os} host",
        f"with {confidence}% confidence",
    ]
    if cloud_provider:
        summary_bits.append(f"hosted on {cloud_provider}")
    if ports_result.open_ports:
        exposed = ", ".join(f"{port.service}/TCP{port.port_number}" for port in ports_result.open_ports[:4])
        summary_bits.append(f"exposing {exposed}")
    if eol_findings:
        summary_bits.append("Some detected software appears aged and should be reviewed")
    ai_summary = ". ".join(summary_bits) + "."

    open_ports = [
        {
            "port": port.port_number,
            "service": port.service,
            "version": port.version,
            "fingerprint": port.fingerprint,
            "risk_level": port.risk_level,
        }
        for port in ports_result.open_ports
    ]

    return OsFingerprintResult(
        target=target,
        ip=ip,
        detected_os=detected_os,
        family=family,
        os_version_estimate=os_version,
        distribution_family=distribution_family,
        kernel_estimate=kernel_estimate,
        device_type=device_type,
        environment=environment,
        hosting_provider=cloud_provider,
        confidence=confidence,
        confidence_label=_confidence_label(confidence),
        os_probabilities=probabilities,
        virtualization_signals=virtualization_signals,
        method="Passive TTL, TCP port, and banner fingerprinting",
        detection_mode="Hybrid Fingerprinting" if tcp_stack.get("mss") else "Passive Fingerprinting",
        evidence=evidence[:8],
        fingerprint_sources=source_breakdown,
        tcp_ip_stack=tcp_stack,
        network_distance={
            "observed_ttl": ttl,
            "estimated_initial_ttl": initial_ttl,
            "estimated_hops": hop_distance,
            "range": f"{max(0, hop_distance - 1)}-{hop_distance + 1} hops" if hop_distance is not None else "Unknown",
        },
        uptime_estimate={
            "value": None,
            "confidence": "unavailable",
            "method": "TCP timestamp uptime estimation requires raw timestamp clock sampling across packets.",
            "note": "Timestamp support is reported in tcp_ip_stack when available.",
        },
        service_os_correlation=correlations[:8],
        cpe_matches=cpes,
        mitre_attack=_mitre(ports_result.open_ports),
        attack_surface_by_os=_attack_surface(family, ports_result.open_ports),
        eol_findings=eol_findings,
        vulnerability_correlation=vuln_correlation,
        fingerprint_timeline=_timeline(ttl, ports_result.open_ports, correlations, confidence),
        hardening_indicators=hardening,
        firewall_detection=firewall,
        honeypot_detection=honeypot,
        risk_score=risk,
        ai_summary=ai_summary,
        internet_exposure=exposure,
        geolocation=geolocation,
        historical_comparison={
            "available": False,
            "summary": "No previous OS fingerprint baseline is available in the current endpoint response.",
            "changes": [],
        },
        scan_quality=quality,
        ttl=ttl,
        open_ports=open_ports,
        scan_duration_seconds=time.time() - start,
        error=ports_result.error,
    )


def _is_public_ip(ip: str | None) -> bool:
    if not ip:
        return False
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (
        parsed.is_private
        or parsed.is_loopback
        or parsed.is_link_local
        or parsed.is_multicast
        or parsed.is_reserved
        or parsed.is_unspecified
    )
