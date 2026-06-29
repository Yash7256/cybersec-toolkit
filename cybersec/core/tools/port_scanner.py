import asyncio
import json
import hashlib
import os
import re
import socket
import ssl
from dataclasses import asdict, dataclass, field
from ipaddress import ip_address
from typing import List, Optional
import time

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from cybersec.config.settings import settings
from cybersec.core.redis_client import RedisKeys, get_shared_redis_client
from cybersec.core.tools.banner_grab import (
    BannerInfo,
    from_bytes,
    grab_http_banner,
    read_passive_banner,
)
from cybersec.core.tools.port_descriptions import get_port_description
from cybersec.core.tools.port_risk import classify_port_risk
from cybersec.core.tools.service_version import parse_http_response, parse_ssh_banner
from cybersec.core.tools.ssl import SSLResult, ssl_audit
from cybersec.core.tools.subdomain import SCREENSHOT_DIR
from cybersec.core.tools.tech_detect import detect_technologies, merge_technologies

# Playwright is an optional dependency for port screenshots.
# Import at module level so tests can patch cybersec.core.tools.port_scanner.async_playwright.
# A lazy ImportError is caught in capture_web_port_screenshots() itself.
try:
    from playwright.async_api import async_playwright
except ImportError:  # pragma: no cover
    async_playwright = None  # type: ignore[assignment,misc]
from cybersec.core.tools.cve_detect import detect_cves_batch, detect_cves_for_version, CVEResult, parse_version_string
from cybersec.core.tools.port_registry import (
    PORT_REGISTRY,
    COMMON_PORTS,
    EXPOSED_SERVICE_PORTS,
    MITRE_PORT_MAPPINGS,
    POTENTIAL_THREATS,
)

@dataclass
class OpenPortDetail:
    port_number: int
    service: str
    status: str
    version: str | None = None
    raw_banner: str | None = None
    welcome_message: str | None = None
    server_response: str | None = None
    risk_level: str = "medium"
    risk_reason: str | None = None
    service_description: str | None = None
    service_security_concern: str | None = None
    technologies: List[str] = field(default_factory=list)
    screenshot: str | None = None
    screenshot_url: str | None = None
    recommendation: str | None = None
    recommendation_reason: str | None = None
    recommendation_priority: str | None = None
    mitre_attack: list[dict] = field(default_factory=list)
    potential_threat: str | None = None
    exploit_availability: dict = field(default_factory=dict)
    misconfigurations: list[dict] = field(default_factory=list)
    exposure_severity: dict = field(default_factory=dict)
    cve_result: CVEResult | None = None
    cve_count: int = 0
    cve_critical_count: int = 0
    cve_high_count: int = 0
    cve_medium_count: int = 0
    cve_low_count: int = 0
    max_cvss_score: float | None = None
    max_cvss_severity: str | None = None
    max_cvss_cve: str | None = None
    fingerprint: dict = field(default_factory=dict)


@dataclass
class PortScanResult:
    target: str
    total_scanned: int
    open_ports_count: int
    open_ports: List[OpenPortDetail]
    scan_duration_seconds: float
    packets_sent: int = 0
    avg_latency_ms: float | None = None
    detected_technologies: List[str] = field(default_factory=list)
    security_score: int = 100
    security_score_factors: list[dict] = field(default_factory=list)
    attack_surface: dict = field(default_factory=dict)
    threat_intelligence: dict = field(default_factory=dict)
    misconfiguration_summary: dict = field(default_factory=dict)
    exposure_summary: dict = field(default_factory=dict)
    attack_paths: dict = field(default_factory=dict)
    attack_simulations: list[dict] = field(default_factory=list)
    recommendations_error: str | None = None
    error: str | None = None


def get_service_for_port(port: int) -> str:
    """Get service name for a port number."""
    info = PORT_REGISTRY.get(port)
    return info.service if info else "Unknown"


SSH_PORTS = {22}
HTTP_PORTS = {80, 443, 8000, 8080, 8443, 8888, 3000, 5000}
SCREENSHOT_PORTS = {80, 443, 8080}
HTTPS_PORTS = {443, 8443}
FTP_PORTS = {21}
PROXY_PORTS = {8080, 3128, 8000, 8888}
WEAK_TLS_CIPHER_MARKERS = {"RC4", "DES", "3DES", "NULL", "EXPORT", "MD5"}
WEB_SECURITY_HEADERS = {
    "content-security-policy": "Content-Security-Policy",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
}
HTTPS_SECURITY_HEADERS = {
    **WEB_SECURITY_HEADERS,
    "strict-transport-security": "Strict-Transport-Security",
}
# Services that send a welcome line immediately on connect
WELCOME_PORTS = {21, 22, 23, 25, 110, 143, 3306, 6379, 27017}
BANNER_PORTS = WELCOME_PORTS | HTTP_PORTS
EXPOSED_SERVICE_PORTS = {
    21: "FTP exposes credentials and file access if not tightly controlled.",
    23: "Telnet sends credentials in cleartext.",
    445: "SMB is sensitive when exposed beyond trusted networks.",
    3306: "MySQL should not be internet-exposed unless strongly restricted.",
    3389: "RDP is a common brute-force and ransomware target.",
    5432: "PostgreSQL should not be internet-exposed unless strongly restricted.",
    5900: "VNC often exposes remote desktop access.",
    6379: "Redis commonly lacks authentication on misconfigured deployments.",
    27017: "MongoDB should not be internet-exposed unless strongly restricted.",
}
ADMIN_SERVICE_PORTS = {22, 23, 445, 3389, 5900, 6379}
DATABASE_PORTS = {3306, 5432, 6379, 27017}
REMOTE_ACCESS_PORTS = {22, 23, 3389, 5900}
EXPOSURE_SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
MITRE_PORT_MAPPINGS = {
    21: [
        ("T1071.002", "Application Layer Protocol: File Transfer Protocols", "Command and Control"),
        ("T1110", "Brute Force", "Credential Access"),
    ],
    22: [
        ("T1110", "Brute Force", "Credential Access"),
        ("T1021.004", "Remote Services: SSH", "Lateral Movement"),
        ("T1078", "Valid Accounts", "Initial Access"),
    ],
    23: [
        ("T1110", "Brute Force", "Credential Access"),
        ("T1021", "Remote Services", "Lateral Movement"),
        ("T1048.003", "Exfiltration Over Unencrypted Protocol", "Exfiltration"),
    ],
    25: [
        ("T1071.003", "Application Layer Protocol: Mail Protocols", "Command and Control"),
        ("T1110", "Brute Force", "Credential Access"),
        ("T1566.001", "Phishing: Spearphishing Attachment", "Initial Access"),
    ],
    53: [
        ("T1071.004", "Application Layer Protocol: DNS", "Command and Control"),
        ("T1595.001", "Active Scanning: Scanning IP Blocks", "Reconnaissance"),
    ],
    80: [
        ("T1190", "Exploit Public-Facing Application", "Initial Access"),
        ("T1071.001", "Application Layer Protocol: Web Protocols", "Command and Control"),
    ],
    443: [
        ("T1190", "Exploit Public-Facing Application", "Initial Access"),
        ("T1071.001", "Application Layer Protocol: Web Protocols", "Command and Control"),
    ],
    445: [
        ("T1021.002", "Remote Services: SMB/Windows Admin Shares", "Lateral Movement"),
        ("T1135", "Network Share Discovery", "Discovery"),
        ("T1110", "Brute Force", "Credential Access"),
    ],
    3306: [
        ("T1110", "Brute Force", "Credential Access"),
        ("T1210", "Exploitation of Remote Services", "Lateral Movement"),
        ("T1190", "Exploit Public-Facing Application", "Initial Access"),
    ],
    3389: [
        ("T1021.001", "Remote Services: Remote Desktop Protocol", "Lateral Movement"),
        ("T1110", "Brute Force", "Credential Access"),
        ("T1078", "Valid Accounts", "Initial Access"),
    ],
    5432: [
        ("T1110", "Brute Force", "Credential Access"),
        ("T1210", "Exploitation of Remote Services", "Lateral Movement"),
        ("T1190", "Exploit Public-Facing Application", "Initial Access"),
    ],
    5900: [
        ("T1021", "Remote Services", "Lateral Movement"),
        ("T1110", "Brute Force", "Credential Access"),
    ],
    6379: [
        ("T1190", "Exploit Public-Facing Application", "Initial Access"),
        ("T1210", "Exploitation of Remote Services", "Lateral Movement"),
        ("T1059", "Command and Scripting Interpreter", "Execution"),
    ],
    8080: [
        ("T1190", "Exploit Public-Facing Application", "Initial Access"),
        ("T1071.001", "Application Layer Protocol: Web Protocols", "Command and Control"),
        ("T1571", "Non-Standard Port", "Defense Evasion"),
    ],
    8443: [
        ("T1190", "Exploit Public-Facing Application", "Initial Access"),
        ("T1071.001", "Application Layer Protocol: Web Protocols", "Command and Control"),
        ("T1571", "Non-Standard Port", "Defense Evasion"),
    ],
    27017: [
        ("T1110", "Brute Force", "Credential Access"),
        ("T1210", "Exploitation of Remote Services", "Lateral Movement"),
        ("T1190", "Exploit Public-Facing Application", "Initial Access"),
    ],
}
MITRE_SERVICE_MAPPINGS = {
    "ssh": MITRE_PORT_MAPPINGS[22],
    "telnet": MITRE_PORT_MAPPINGS[23],
    "smb": MITRE_PORT_MAPPINGS[445],
    "rdp": MITRE_PORT_MAPPINGS[3389],
    "ftp": MITRE_PORT_MAPPINGS[21],
    "http": MITRE_PORT_MAPPINGS[80],
    "http-proxy": MITRE_PORT_MAPPINGS[8080],
    "https": MITRE_PORT_MAPPINGS[443],
    "https-alt": MITRE_PORT_MAPPINGS[8443],
    "mysql": MITRE_PORT_MAPPINGS[3306],
    "postgresql": MITRE_PORT_MAPPINGS[5432],
    "redis": MITRE_PORT_MAPPINGS[6379],
    "mongodb": MITRE_PORT_MAPPINGS[27017],
    "vnc": MITRE_PORT_MAPPINGS[5900],
}
POTENTIAL_THREATS = {
    21: "Credential attacks and unauthorized file transfer are possible on FTP service.",
    22: "Brute force attempts possible on SSH service.",
    23: "Cleartext credential theft and brute force attempts are possible on Telnet service.",
    25: "Mail relay abuse, account brute force, or phishing infrastructure abuse may be possible.",
    53: "DNS tunneling, reconnaissance, or zone-transfer probing may be possible.",
    80: "Public web exploitation and web reconnaissance are possible on HTTP service.",
    443: "Public web exploitation and encrypted command-and-control traffic may blend into HTTPS service.",
    445: "SMB exposure can enable lateral movement, share discovery, and credential attacks.",
    3306: "Database brute force and remote service exploitation may be possible on MySQL.",
    3389: "Brute force attempts and remote desktop lateral movement are possible on RDP.",
    5432: "Database brute force and remote service exploitation may be possible on PostgreSQL.",
    5900: "Remote desktop takeover attempts may be possible on VNC.",
    6379: "Redis exposure can lead to remote exploitation or command execution if misconfigured.",
    8080: "Public web exploitation may be possible on the alternate HTTP service.",
    8443: "Public web exploitation may be possible on the alternate HTTPS service.",
    27017: "Database exposure and unauthorized data access may be possible on MongoDB.",
}
CURATED_EXPLOIT_RULES = [
    {
        "service": "apache",
        "versions": {"2.4.49", "2.4.50"},
        "title": "Apache HTTP Server path traversal / RCE",
        "cves": ["CVE-2021-41773", "CVE-2021-42013"],
        "exploitdb": True,
        "metasploit": True,
        "module": "multi/http/apache_path_traversal",
    },
    {
        "service": "vsftpd",
        "versions": {"2.3.4"},
        "title": "vsftpd 2.3.4 backdoor command execution",
        "cves": ["CVE-2011-2523"],
        "exploitdb": True,
        "metasploit": True,
        "module": "unix/ftp/vsftpd_234_backdoor",
    },
    {
        "service": "proftpd",
        "versions": {"1.3.3c"},
        "title": "ProFTPD mod_copy command execution",
        "cves": ["CVE-2015-3306"],
        "exploitdb": True,
        "metasploit": True,
        "module": "unix/ftp/proftpd_modcopy_exec",
    },
    {
        "service": "samba",
        "versions": {"3.0.20", "3.0.21", "3.0.22", "3.0.23", "3.0.24", "3.0.25"},
        "title": "Samba username map script command execution",
        "cves": ["CVE-2007-2447"],
        "exploitdb": True,
        "metasploit": True,
        "module": "multi/samba/usermap_script",
    },
    {
        "service": "redis",
        "versions": set(),
        "title": "Redis unauthenticated write/replication abuse patterns",
        "cves": [],
        "exploitdb": True,
        "metasploit": False,
        "module": None,
    },
]
SPAMHAUS_ZONES = {
    "zen.spamhaus.org": "Spamhaus ZEN",
}
KNOWN_BOTNET_IPS: set[str] = set()


def _probe_timeout(port: int, timeout: float) -> float:
    """Banner grabs need a bit more time than a bare connect check."""
    if port in BANNER_PORTS:
        return max(timeout, 3.0)
    return timeout


def _ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _version_from_banner(port: int, raw: bytes, http: bool) -> str | None:
    if not raw:
        return None
    if http:
        return parse_http_response(raw)
    if port in SSH_PORTS:
        return parse_ssh_banner(raw)
    return None


def _fingerprint_method(port: OpenPortDetail) -> str:
    if port.port_number in HTTP_PORTS:
        return "HTTP banner and technology detection"
    if port.port_number in WELCOME_PORTS:
        return "Protocol banner"
    return "TCP port mapping"


def _calculate_fingerprint_confidence(port: OpenPortDetail) -> dict:
    evidence = []
    score = 35

    if port.port_number in COMMON_PORTS:
        score += 12
        evidence.append("known port mapping")
    if port.raw_banner:
        score += 20
        evidence.append("raw banner captured")
    if port.server_response:
        score += 12
        evidence.append("server response captured")
    if port.welcome_message:
        score += 10
        evidence.append("welcome banner captured")
    if port.version:
        score += 24
        evidence.append("version string parsed")
        parsed = parse_version_string(port.version)
        if parsed and re.search(r"\d+\.\d+", parsed[1]):
            score += 8
            evidence.append("specific version number")
    if port.technologies:
        score += min(12, 4 * len(port.technologies))
        evidence.append("technology signatures matched")

    if not (port.raw_banner or port.server_response or port.welcome_message or port.version):
        score -= 18
        evidence.append("no banner evidence")
    if port.service == "Unknown":
        score -= 10
        evidence.append("unknown service")

    confidence = max(20, min(99, score))
    detected = port.version or (
        f"{port.service} service" if port.service and port.service != "Unknown" else f"TCP/{port.port_number}"
    )
    return {
        "detected": detected,
        "confidence": confidence,
        "method": _fingerprint_method(port),
        "evidence": evidence[:5],
    }


def add_service_fingerprints(open_ports: list[OpenPortDetail]) -> None:
    for port in open_ports:
        port.fingerprint = _calculate_fingerprint_confidence(port)


def _apply_banner(detail: OpenPortDetail, banner: BannerInfo) -> None:
    detail.raw_banner = banner.raw_banner
    detail.welcome_message = banner.welcome_message
    detail.server_response = banner.server_response


def _screenshot_url(hostname: str, port: int) -> str:
    scheme = "https" if port in HTTPS_PORTS else "http"
    host_part = hostname if port in {80, 443} else f"{hostname}:{port}"
    return f"{scheme}://{host_part}"


def _safe_screenshot_filename(hostname: str, port: int) -> str:
    safe_host = re.sub(r"[^A-Za-z0-9_.-]+", "_", hostname).strip("._") or "target"
    return f"portscan_{safe_host}_{port}.png"


# Total wall-clock cap for the entire screenshot pass (seconds).
_SCREENSHOT_TOTAL_TIMEOUT = 30.0
# Per-page navigation + render timeout (seconds).
_SCREENSHOT_NAV_TIMEOUT = 8_000  # Playwright uses milliseconds


async def capture_web_port_screenshots(
    target: str,
    open_ports: list[OpenPortDetail],
    screenshot_dir: str | None = None,
) -> None:
    """
    Capture best-effort page previews for open web ports using Playwright/Chromium.

    SECURITY NOTE — the target host is untrusted:
      * JavaScript dialogs (alert/confirm/prompt) are auto-dismissed.
      * File downloads are rejected before they start.
      * A strict navigation timeout prevents indefinitely-hung page loads.
      * The overall function is capped at _SCREENSHOT_TOTAL_TIMEOUT seconds so a
        single unresponsive target cannot stall the entire scan.
      * The sandbox is kept enabled wherever possible; --no-sandbox is only
        added when the process is running as root (unavoidable in many container
        environments), because the sandbox requires a non-root uid to function.
    """
    if not settings.ENABLE_PORT_SCREENSHOTS:
        return

    web_ports = [p for p in open_ports if p.port_number in SCREENSHOT_PORTS]
    if not web_ports:
        return

    dir_path = screenshot_dir or SCREENSHOT_DIR
    os.makedirs(dir_path, exist_ok=True)

    if async_playwright is None:
        # playwright not installed (ImportError at module load, common in CI without browsers)
        return
    # The sandbox is a meaningful security boundary; keep it when we can.
    running_as_root = os.getuid() == 0 if hasattr(os, "getuid") else False
    launch_args = ["--no-sandbox", "--disable-setuid-sandbox"] if running_as_root else []
    # Additional hardening regardless of user:
    launch_args += [
        "--disable-dev-shm-usage",
        "--disable-gpu",
        "--disable-extensions",
        "--disable-background-networking",
        "--disable-default-apps",
        "--no-first-run",
        "--disable-sync",
    ]

    async def _take_screenshots() -> None:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True, args=launch_args)
            try:
                for port_detail in web_ports:
                    url = _screenshot_url(target, port_detail.port_number)
                    filename = _safe_screenshot_filename(target, port_detail.port_number)
                    filepath = os.path.join(dir_path, filename)

                    page = None
                    try:
                        # new_context with accept_downloads=False blocks drive-by downloads.
                        ctx = await browser.new_context(
                            viewport={"width": 640, "height": 360},
                            accept_downloads=False,
                            ignore_https_errors=True,
                            java_script_enabled=True,  # needed to render most pages
                        )
                        page = await ctx.new_page()

                        # Auto-dismiss JS dialogs — never let an untrusted page
                        # pause execution with alert()/confirm()/prompt().
                        page.on("dialog", lambda d: asyncio.ensure_future(d.dismiss()))

                        await page.goto(
                            url,
                            wait_until="networkidle",
                            timeout=_SCREENSHOT_NAV_TIMEOUT,
                        )
                        await page.screenshot(path=filepath, full_page=False)
                        port_detail.screenshot = filename
                        port_detail.screenshot_url = f"/screenshots/{filename}"
                    except Exception:
                        # One port failing must not abort screenshots for the others.
                        pass
                    finally:
                        if page:
                            try:
                                await page.close()
                            except Exception:
                                pass
                        try:
                            await ctx.close()  # type: ignore[possibly-undefined]
                        except Exception:
                            pass
            finally:
                try:
                    await browser.close()
                except Exception:
                    pass

    try:
        await asyncio.wait_for(_take_screenshots(), timeout=_SCREENSHOT_TOTAL_TIMEOUT)
    except asyncio.TimeoutError:
        pass  # Ran out of time — return whatever was captured so far.


def _recommendation_payload(target: str, open_ports: list[OpenPortDetail]) -> dict:
    return {
        "target": target,
        "open_ports": [
            {
                "port_number": p.port_number,
                "service": p.service,
                "status": p.status,
                "version": p.version,
                "risk_level": p.risk_level,
                "risk_reason": p.risk_reason,
                "service_description": p.service_description,
                "service_security_concern": p.service_security_concern,
                "technologies": p.technologies,
                "cve_count": p.cve_count,
                "cve_critical_count": p.cve_critical_count,
                "cve_high_count": p.cve_high_count,
            }
            for p in open_ports
        ],
    }


def _parse_recommendations(raw: str) -> dict[int, dict]:
    data = json.loads(raw)
    items = data.get("recommendations", [])
    parsed = {}
    if not isinstance(items, list):
        return parsed

    for item in items:
        if not isinstance(item, dict):
            continue
        try:
            port = int(item.get("port_number"))
        except (TypeError, ValueError):
            continue
        parsed[port] = item
    return parsed


async def add_ai_recommendations(
    target: str,
    open_ports: list[OpenPortDetail],
) -> str | None:
    """Ask Groq for concise remediation guidance and attach it to each port."""
    if not open_ports:
        return None

    # Build a stable fingerprint key from (port, service, version) tuples.
    _fp = hashlib.sha256(
        str(sorted((p.port_number, p.service or "", p.version or "") for p in open_ports)).encode()
    ).hexdigest()[:16]
    cache_key = RedisKeys.ai_recommendations(_fp)
    redis = get_shared_redis_client()

    if redis is not None:
        try:
            cached = await redis.get(cache_key)
            if cached is not None:
                recommendations: dict[int, dict] = {int(k): v for k, v in json.loads(cached).items()}
                for port in open_ports:
                    rec = recommendations.get(port.port_number)
                    if not rec:
                        continue
                    if rec.get("recommendation"):
                        port.recommendation = str(rec["recommendation"]).strip()
                    if rec.get("reason"):
                        port.recommendation_reason = str(rec["reason"]).strip()
                    priority = str(rec.get("priority") or "").strip().lower()
                    if priority in {"critical", "high", "medium", "low"}:
                        port.recommendation_priority = priority
                return None
        except Exception:
            logger.warning("Redis unavailable for ai_recs cache read (fp=%s)", _fp)

    try:
        from cybersec.integrations.ai.groq_client import groq_client
    except Exception as e:
        return f"AI recommendations unavailable: {e}"

    system_prompt = """
You are a senior cybersecurity remediation assistant.
Return ONLY valid JSON. Do not use markdown.
For each open port, provide one concise recommended action that a defender can take.
Be specific to the service, version, risk, and port. Prefer practical remediation.
If a service is inherently insecure, say so and recommend a safer replacement.

JSON schema:
{
  "recommendations": [
    {
      "port_number": 23,
      "priority": "critical|high|medium|low",
      "reason": "Port 23 (Telnet) is insecure because it sends credentials in cleartext.",
      "recommendation": "Disable Telnet and use SSH with key-based authentication."
    }
  ]
}
"""
    messages = [
        {
            "role": "user",
            "content": json.dumps(_recommendation_payload(target, open_ports), ensure_ascii=False),
        }
    ]

    try:
        raw = await asyncio.wait_for(
            groq_client.chat(
                messages,
                system_prompt,
                response_format={"type": "json_object"},
            ),
            timeout=25.0,
        )
        recommendations = _parse_recommendations(raw)
    except Exception as e:
        return f"AI recommendations failed: {e}"

    for port in open_ports:
        rec = recommendations.get(port.port_number)
        if not rec:
            continue
        recommendation = str(rec.get("recommendation") or "").strip()
        reason = str(rec.get("reason") or "").strip()
        priority = str(rec.get("priority") or "").strip().lower()
        if recommendation:
            port.recommendation = recommendation
        if reason:
            port.recommendation_reason = reason
        if priority in {"critical", "high", "medium", "low"}:
            port.recommendation_priority = priority

    return None


def _score_factor(category: str, label: str, penalty: int, severity: str = "medium") -> dict:
    return {
        "category": category,
        "label": label,
        "penalty": penalty,
        "severity": severity,
    }


def _surface_factor(category: str, label: str, weight: int, severity: str = "medium") -> dict:
    return {
        "category": category,
        "label": label,
        "weight": weight,
        "severity": severity,
    }


def _unknown_bool_label(value: bool | None) -> str:
    if value is True:
        return "Yes"
    if value is False:
        return "No"
    return "Unknown"


def _version_matches(rule_versions: set[str], version: str | None) -> bool:
    if not rule_versions:
        return True
    return bool(version and version in rule_versions)


def add_exploit_availability(open_ports: list[OpenPortDetail]) -> None:
    """Attach best-effort public exploit availability from local rules and CVE signals."""
    for port in open_ports:
        parsed = parse_version_string(port.version or "")
        parsed_service, parsed_version = parsed if parsed else ((port.service or "").lower(), None)
        cve_ids = {
            cve.cve_id
            for cve in (port.cve_result.cves if port.cve_result else [])
            if getattr(cve, "cve_id", None)
        }

        matched_rule = None
        for rule in CURATED_EXPLOIT_RULES:
            service_match = rule["service"] in parsed_service.lower() or rule["service"] in (port.service or "").lower()
            version_match = _version_matches(rule["versions"], parsed_version)
            cve_match = bool(cve_ids.intersection(rule["cves"]))
            if service_match and (version_match or cve_match):
                matched_rule = rule
                break

        public_available: bool | None = None
        exploitdb_available: bool | None = None
        metasploit_available: bool | None = None
        module = None
        evidence = []

        if matched_rule:
            public_available = True
            exploitdb_available = matched_rule["exploitdb"]
            metasploit_available = matched_rule["metasploit"]
            module = matched_rule["module"]
            evidence.append(matched_rule["title"])
            evidence.extend(matched_rule["cves"])
        elif port.cve_critical_count or port.cve_high_count:
            public_available = True
            evidence.append("High-impact CVE signals found; public exploit availability should be verified.")
        elif port.cve_count:
            public_available = None
            evidence.append("Known CVEs found, but no curated public exploit match.")
        else:
            public_available = False

        display_name = port.version or f"{port.service} on port {port.port_number}"
        port.exploit_availability = {
            "service_version": display_name,
            "public_exploit_available": public_available,
            "exploitdb_available": exploitdb_available,
            "metasploit_available": metasploit_available,
            "metasploit_module": module,
            "exploitdb": _unknown_bool_label(exploitdb_available),
            "metasploit": "Available" if metasploit_available else ("Not found" if metasploit_available is False else "Unknown"),
            "evidence": [item for item in evidence if item],
        }


def _misconfiguration(
    category: str,
    title: str,
    severity: str,
    evidence: str,
    recommendation: str,
) -> dict:
    return {
        "category": category,
        "title": title,
        "severity": severity,
        "evidence": evidence,
        "recommendation": recommendation,
    }


def _http_response_text(port: OpenPortDetail) -> str:
    return "\n".join(
        part for part in [port.server_response, port.raw_banner, port.welcome_message] if part
    )


def _parse_http_headers(response: str) -> dict[str, str]:
    if not response:
        return {}
    headers: dict[str, str] = {}
    for line in response.replace("\r\n", "\n").split("\n")[1:]:
        if not line.strip():
            break
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        headers[name.strip().lower()] = value.strip()
    return headers


def _detect_http_misconfigurations(port: OpenPortDetail) -> list[dict]:
    response = _http_response_text(port)
    if not response:
        return []

    findings = []
    body_hint = response.lower()
    if (
        re.search(r"<title>\s*index of\s*/?", body_hint, re.IGNORECASE)
        or re.search(r"<h1>\s*index of\s*/?", body_hint, re.IGNORECASE)
        or "directory listing for /" in body_hint
        or "parent directory" in body_hint and "last modified" in body_hint
    ):
        findings.append(_misconfiguration(
            "directory_listing",
            "Directory listing enabled",
            "high",
            "The HTTP response appears to expose an auto-generated directory index.",
            "Disable directory indexes and require authentication for file browsing paths.",
        ))

    headers = _parse_http_headers(response)
    required = HTTPS_SECURITY_HEADERS if port.port_number in HTTPS_PORTS else WEB_SECURITY_HEADERS
    missing = [display for key, display in required.items() if key not in headers]
    if missing:
        shown = ", ".join(missing[:4])
        findings.append(_misconfiguration(
            "missing_security_headers",
            "Missing security headers",
            "medium",
            f"Missing: {shown}.",
            "Add the missing browser security headers at the web server or application gateway.",
        ))

    return findings


async def _probe_anonymous_ftp(target: str, port: int, timeout: float) -> dict | None:
    reader = writer = None
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(target, port), timeout=timeout)
        await asyncio.wait_for(reader.read(256), timeout=timeout)
        writer.write(b"USER anonymous\r\n")
        await writer.drain()
        user_reply = await asyncio.wait_for(reader.read(256), timeout=timeout)
        writer.write(b"PASS anonymous@\r\n")
        await writer.drain()
        pass_reply = await asyncio.wait_for(reader.read(512), timeout=timeout)
        combined = (user_reply + pass_reply).decode("utf-8", errors="replace")
        if "230" in combined:
            return _misconfiguration(
                "anonymous_ftp",
                "Anonymous FTP login enabled",
                "critical",
                "FTP accepted USER anonymous with an anonymous password.",
                "Disable anonymous FTP access or restrict it to a hardened read-only drop zone.",
            )
    except Exception:
        return None
    finally:
        if writer:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
    return None


async def _probe_open_proxy(target: str, port: int, timeout: float) -> dict | None:
    reader = writer = None
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(target, port), timeout=timeout)
        request = (
            "GET http://example.com/ HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "User-Agent: CyberSecPortScanner/1.0\r\n"
            "Connection: close\r\n\r\n"
        ).encode()
        writer.write(request)
        await writer.drain()
        data = await asyncio.wait_for(reader.read(2048), timeout=max(timeout, 3.0))
        text = data.decode("utf-8", errors="replace")
        head = text.split("\r\n\r\n", 1)[0]
        if (
            "Example Domain" in text
            or (
                re.search(r"HTTP/\d(?:\.\d)?\s+20\d", head)
                and "407 Proxy Authentication Required" not in head
                and "403 Forbidden" not in head
            )
        ):
            return _misconfiguration(
                "open_proxy",
                "Open proxy detected",
                "critical",
                "The service accepted an absolute-form HTTP proxy request.",
                "Disable unauthenticated proxying or restrict proxy access to trusted networks only.",
            )
    except Exception:
        return None
    finally:
        if writer:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
    return None


async def _detect_tls_misconfiguration(
    target: str,
    port: OpenPortDetail,
    ssl_cache: dict[int, SSLResult] | None = None,
    allow_private: bool = False,
) -> list[dict]:
    if port.port_number not in HTTPS_PORTS:
        return []
    try:
        result = ssl_cache[port.port_number] if (ssl_cache and port.port_number in ssl_cache) else await ssl_audit(target, port.port_number, allow_private=allow_private)
    except Exception:
        return [_misconfiguration(
            "weak_ssl",
            "Weak SSL/TLS configuration",
            "medium",
            "TLS audit failed for this service.",
            "Review TLS configuration and verify supported protocols, ciphers, and certificate chain.",
        )]

    findings = []
    if result.error:
        findings.append(_misconfiguration(
            "weak_ssl",
            "Weak SSL/TLS configuration",
            "medium",
            result.error,
            "Review TLS configuration and certificate deployment for this HTTPS service.",
        ))
        return findings

    cipher_name = result.cipher_suite or ""
    weak_cipher = any(marker in cipher_name.upper() for marker in WEAK_TLS_CIPHER_MARKERS)
    if weak_cipher or (result.tls_version in {"TLSv1", "TLSv1.1"}) or not result.supports_tls12:
        evidence = []
        if cipher_name:
            evidence.append(f"Cipher: {cipher_name}")
        if result.tls_version:
            evidence.append(f"Negotiated: {result.tls_version}")
        if not result.supports_tls12:
            evidence.append("TLS 1.2 not supported")
        findings.append(_misconfiguration(
            "weak_ssl",
            "Weak SSL ciphers",
            "high",
            "; ".join(evidence) or "Weak TLS settings were detected.",
            "Disable legacy protocols and weak ciphers; require TLS 1.2 or newer with modern cipher suites.",
        ))

    if result.is_self_signed:
        findings.append(_misconfiguration(
            "weak_ssl",
            "Self-signed SSL certificate",
            "medium",
            "The HTTPS service uses a self-signed certificate.",
            "Use a certificate issued by a trusted CA for public-facing services.",
        ))
    if result.cert and result.cert.is_expired:
        findings.append(_misconfiguration(
            "weak_ssl",
            "Expired SSL certificate",
            "high",
            "The HTTPS certificate is expired.",
            "Renew and deploy a valid certificate for this service.",
        ))
    return findings


def _misconfiguration_summary(open_ports: list[OpenPortDetail]) -> dict:
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    categories = set()
    total = 0
    for port in open_ports:
        for finding in port.misconfigurations:
            total += 1
            severity = str(finding.get("severity") or "medium").lower()
            severity_counts[severity if severity in severity_counts else "medium"] += 1
            category = str(finding.get("category") or "").strip()
            if category:
                categories.add(category)
    return {
        "total": total,
        "critical": severity_counts["critical"],
        "high": severity_counts["high"],
        "medium": severity_counts["medium"],
        "low": severity_counts["low"],
        "categories": sorted(categories),
    }


def _is_public_ip(ip: str | None) -> bool:
    if not ip:
        return False
    try:
        parsed = ip_address(ip)
    except ValueError:
        return False
    return not (
        parsed.is_private
        or parsed.is_loopback
        or parsed.is_reserved
        or parsed.is_link_local
        or parsed.is_multicast
        or parsed.is_unspecified
    )


# Cloud / hypervisor metadata addresses that must never be scanned externally.
_METADATA_BLOCKLIST: frozenset[str] = frozenset({
    "169.254.169.254",   # AWS / Azure / GCP instance metadata (IPv4 link-local)
    "fd00:ec2::254",     # AWS instance metadata (IPv6)
    "metadata.google.internal",  # GCP – resolved string form; handled by hostname too
    "100.100.100.200",   # Alibaba Cloud metadata
})


def _is_scan_target_allowed(ip: str) -> bool:
    """
    Return True when *ip* is safe to scan.

    Blocks any address that is private, loopback, link-local, reserved,
    multicast, unspecified, or in the hardcoded cloud-metadata blocklist.
    This is intentionally strict – the only way to bypass it is the
    ``allow_private`` flag on the scan functions (gated by authentication
    in the API layer).
    """
    if ip in _METADATA_BLOCKLIST:
        return False
    try:
        parsed = ip_address(ip)
    except ValueError:
        return False
    return not (
        parsed.is_private
        or parsed.is_loopback
        or parsed.is_link_local
        or parsed.is_reserved
        or parsed.is_multicast
        or parsed.is_unspecified
    )


_BLOCKED_SCAN_ERROR = (
    "Scanning private, loopback, or cloud-metadata addresses is not permitted"
)


def _exposure_level(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 35:
        return "medium"
    return "low"


def _promote_risk_level(current: str, incoming: str) -> str:
    current_rank = EXPOSURE_SEVERITY_RANK.get((current or "medium").lower(), 2)
    incoming_rank = EXPOSURE_SEVERITY_RANK.get((incoming or "medium").lower(), 2)
    return incoming if incoming_rank > current_rank else current


def _exposure_finding(port: OpenPortDetail, public_exposure: bool, severity: str) -> str:
    prefix = f"{severity.title()} Exposure"
    if public_exposure and port.port_number == 3389:
        return f"{prefix}: RDP is publicly reachable; this scan did not verify a VPN or access-gateway boundary."
    if public_exposure and port.port_number == 22:
        return f"{prefix}: SSH is publicly reachable and commonly targeted for credential attacks."
    if public_exposure and port.port_number == 23:
        return f"{prefix}: Telnet is publicly reachable and uses cleartext authentication."
    if public_exposure and port.port_number == 445:
        return f"{prefix}: SMB is publicly reachable, which increases share-enumeration and lateral-movement risk."
    if public_exposure and port.port_number in DATABASE_PORTS:
        return f"{prefix}: {port.service} database service is publicly reachable."
    if public_exposure and port.port_number in HTTP_PORTS:
        return f"{prefix}: Web service is publicly reachable and adds application attack surface."
    if public_exposure:
        return f"{prefix}: {port.service} on TCP/{port.port_number} is reachable from the internet."
    return f"{prefix}: {port.service} on TCP/{port.port_number} is reachable on the scanned network."


def _exposure_recommendation(port: OpenPortDetail, public_exposure: bool) -> str:
    if public_exposure and port.port_number == 3389:
        return "Place RDP behind a VPN or zero-trust access gateway, restrict source IPs, and require MFA."
    if public_exposure and port.port_number == 22:
        return "Restrict SSH to trusted IPs or VPN, disable password login, and enforce key-based authentication with MFA where possible."
    if public_exposure and port.port_number == 23:
        return "Disable Telnet and use SSH over a restricted management network."
    if public_exposure and port.port_number == 445:
        return "Block SMB from the internet and allow it only inside trusted private networks."
    if public_exposure and port.port_number in DATABASE_PORTS:
        return "Bind the database to private interfaces, require authentication, and allow access only from application hosts or VPN ranges."
    if public_exposure and port.port_number in HTTP_PORTS:
        return "Keep the web stack patched, enforce TLS/security headers, and place administrative paths behind authentication."
    return "Restrict access to trusted networks and close the service if it is not required."


def calculate_exposure_severity(
    ip: str | None,
    open_ports: list[OpenPortDetail],
    threat_intelligence: dict | None = None,
) -> dict:
    """Calculate dynamic exposure severity from context, not only static port risk."""
    public_exposure = _is_public_ip(ip)
    reputation = (threat_intelligence or {}).get("reputation", "Unknown")
    summary_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    highest = {"severity": "low", "score": 0, "finding": "No open-port exposure findings were generated.", "port": None}

    for port in open_ports:
        score = 10
        factors = []
        if public_exposure:
            score += 20
            factors.append("Publicly reachable IP")
        else:
            factors.append("Reachable on scanned network")

        if port.port_number in REMOTE_ACCESS_PORTS:
            score += 30
            factors.append("Remote access service")
        if port.port_number in ADMIN_SERVICE_PORTS:
            score += 18
            factors.append("Administrative service")
        if port.port_number in DATABASE_PORTS:
            score += 24
            factors.append("Database service")
        if port.port_number in HTTP_PORTS:
            score += 10
            factors.append("Web application surface")

        if port.port_number == 3389 and public_exposure:
            score += 35
            factors.append("RDP public reachability; VPN boundary not verified")
        elif port.port_number == 23:
            score += 30
            factors.append("Cleartext Telnet service")
        elif port.port_number == 445 and public_exposure:
            score += 30
            factors.append("Internet-exposed SMB")

        if port.cve_critical_count:
            score += min(25, port.cve_critical_count * 12)
            factors.append("Critical CVE signals")
        elif port.cve_high_count:
            score += min(18, port.cve_high_count * 8)
            factors.append("High CVE signals")
        elif port.cve_count:
            score += 6
            factors.append("Known CVE signals")

        if port.exploit_availability.get("public_exploit_available") is True:
            score += 20
            factors.append("Curated public-exploit signal")

        misconfig_severities = {
            str(item.get("severity") or "medium").lower()
            for item in port.misconfigurations
        }
        if "critical" in misconfig_severities:
            score += 25
            factors.append("Critical misconfiguration")
        elif "high" in misconfig_severities:
            score += 15
            factors.append("High misconfiguration")
        elif "medium" in misconfig_severities:
            score += 8
            factors.append("Medium misconfiguration")

        if reputation == "Malicious":
            score += 18
            factors.append("Malicious IP reputation")
        elif reputation == "Suspicious":
            score += 10
            factors.append("Suspicious IP reputation")

        score = min(100, score)
        severity = _exposure_level(score)
        finding = _exposure_finding(port, public_exposure, severity)
        port.exposure_severity = {
            "score": score,
            "severity": severity,
            "public_exposure": public_exposure,
            "finding": finding,
            "factors": factors[:8],
            "recommendation": _exposure_recommendation(port, public_exposure),
        }
        promoted = _promote_risk_level(port.risk_level, severity)
        if promoted != port.risk_level:
            port.risk_level = promoted
            port.risk_reason = finding

        summary_counts[severity] += 1
        if score > highest["score"]:
            highest = {
                "severity": severity,
                "score": score,
                "finding": finding,
                "port": port.port_number,
            }

    return {
        "public_exposure": public_exposure,
        "highest_severity": highest["severity"],
        "highest_score": highest["score"],
        "highest_finding": highest["finding"],
        "highest_port": highest["port"],
        "critical": summary_counts["critical"],
        "high": summary_counts["high"],
        "medium": summary_counts["medium"],
        "low": summary_counts["low"],
    }


async def detect_misconfigurations(
    target: str,
    open_ports: list[OpenPortDetail],
    timeout: float,
    ssl_cache: dict[int, SSLResult] | None = None,
    allow_private: bool = False,
) -> dict:
    """Attach best-effort misconfiguration findings to each open port."""
    if not open_ports:
        return _misconfiguration_summary(open_ports)

    async def detect_for_port(port: OpenPortDetail) -> None:
        findings = []
        if port.port_number in HTTP_PORTS:
            findings.extend(_detect_http_misconfigurations(port))
        if port.port_number in HTTPS_PORTS:
            findings.extend(await _detect_tls_misconfiguration(target, port, ssl_cache, allow_private=allow_private))
        if port.port_number in FTP_PORTS:
            ftp_finding = await _probe_anonymous_ftp(target, port.port_number, min(max(timeout, 2.0), 5.0))
            if ftp_finding:
                findings.append(ftp_finding)
        if port.port_number in PROXY_PORTS:
            proxy_finding = await _probe_open_proxy(target, port.port_number, min(max(timeout, 2.0), 5.0))
            if proxy_finding:
                findings.append(proxy_finding)
        port.misconfigurations = findings

    await asyncio.gather(*(detect_for_port(port) for port in open_ports))
    return _misconfiguration_summary(open_ports)


def _empty_threat_intel(ip: str | None, reputation: str, summary: str, error: str | None = None) -> dict:
    return {
        "ip": ip,
        "reputation": reputation,
        "summary": summary,
        "reported_times": 0,
        "abuse_confidence_score": None,
        "abuseipdb": {
            "checked": False,
            "available": False,
            "reported_times": None,
            "abuse_confidence_score": None,
        },
        "spamhaus": {
            "checked": False,
            "listed": False,
            "zones": [],
        },
        "known_botnet": False,
        "sources": [],
        "error": error,
    }


async def _spamhaus_check(ip: str) -> dict:
    try:
        parsed = ip_address(ip)
    except ValueError:
        return {"checked": False, "listed": False, "zones": [], "error": "Invalid IP address"}
    if parsed.version != 4 or parsed.is_private or parsed.is_loopback or parsed.is_reserved:
        return {"checked": False, "listed": False, "zones": [], "error": None}

    reversed_ip = ".".join(reversed(ip.split(".")))
    loop = asyncio.get_running_loop()
    listed_zones = []
    errors = []

    for zone, label in SPAMHAUS_ZONES.items():
        query = f"{reversed_ip}.{zone}"
        try:
            await loop.getaddrinfo(query, None, family=socket.AF_INET)
            listed_zones.append({"zone": zone, "name": label})
        except socket.gaierror:
            continue
        except Exception as e:
            errors.append(str(e))

    return {
        "checked": True,
        "listed": bool(listed_zones),
        "zones": listed_zones,
        "error": "; ".join(errors) if errors else None,
    }


async def _abuseipdb_check(ip: str) -> dict:
    if not settings.ABUSEIPDB_API_KEY:
        return {
            "checked": False,
            "available": False,
            "reported_times": None,
            "abuse_confidence_score": None,
            "error": "ABUSEIPDB_API_KEY is not configured",
        }

    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={
                    "Key": settings.ABUSEIPDB_API_KEY,
                    "Accept": "application/json",
                },
                params={
                    "ipAddress": ip,
                    "maxAgeInDays": settings.THREAT_INTEL_MAX_AGE_DAYS,
                },
            )
            resp.raise_for_status()
            data = resp.json().get("data", {})
    except Exception as e:
        return {
            "checked": True,
            "available": False,
            "reported_times": None,
            "abuse_confidence_score": None,
            "error": str(e),
        }

    return {
        "checked": True,
        "available": True,
        "reported_times": data.get("totalReports") or 0,
        "abuse_confidence_score": data.get("abuseConfidenceScore"),
        "country_code": data.get("countryCode"),
        "usage_type": data.get("usageType"),
        "isp": data.get("isp"),
        "domain": data.get("domain"),
        "last_reported_at": data.get("lastReportedAt"),
        "error": None,
    }


async def check_threat_intelligence(ip: str | None) -> dict:
    if not ip:
        return _empty_threat_intel(None, "Unknown", "No resolved IP was available for reputation checks.")

    try:
        parsed = ip_address(ip)
    except ValueError:
        return _empty_threat_intel(ip, "Unknown", "Resolved address was not a valid IP.", "Invalid IP address")

    if parsed.is_private or parsed.is_loopback or parsed.is_reserved:
        return _empty_threat_intel(
            ip,
            "Private/Local",
            "Private, loopback, or reserved IPs are not checked against public abuse databases.",
        )

    # --- Redis cache check ---
    redis = get_shared_redis_client()
    cache_key = RedisKeys.threat_intel(ip)
    if redis is not None:
        try:
            cached = await redis.get(cache_key)
            if cached is not None:
                return json.loads(cached)
        except Exception:
            logger.warning("Redis unavailable for threat_intel cache read (ip=%s)", ip)

    abuseipdb, spamhaus = await asyncio.gather(
        _abuseipdb_check(ip),
        _spamhaus_check(ip),
    )
    reported_times = abuseipdb.get("reported_times") or 0
    abuse_score = abuseipdb.get("abuse_confidence_score")
    known_botnet = ip in KNOWN_BOTNET_IPS

    sources = []
    if abuseipdb.get("checked"):
        sources.append("AbuseIPDB")
    if spamhaus.get("checked"):
        sources.append("Spamhaus")
    if known_botnet:
        sources.append("Known botnet list")

    reputation = "Clean"
    if known_botnet or spamhaus.get("listed") or (abuse_score is not None and abuse_score >= 75):
        reputation = "Malicious"
    elif reported_times > 0 or (abuse_score is not None and abuse_score >= 25):
        reputation = "Suspicious"
    elif not abuseipdb.get("checked") and not spamhaus.get("checked"):
        reputation = "Unknown"

    if reputation == "Malicious":
        summary = f"IP Reputation: Malicious. Reported {reported_times} time(s) for abuse."
    elif reputation == "Suspicious":
        summary = f"IP Reputation: Suspicious. Reported {reported_times} time(s) for abuse."
    elif reputation == "Clean":
        summary = "IP Reputation: Clean. No abuse reports or blocklist hits were found in checked sources."
    else:
        summary = "IP Reputation: Unknown. No threat intelligence source returned a usable result."

    result = {
        "ip": ip,
        "reputation": reputation,
        "summary": summary,
        "reported_times": reported_times,
        "abuse_confidence_score": abuse_score,
        "abuseipdb": abuseipdb,
        "spamhaus": spamhaus,
        "known_botnet": known_botnet,
        "sources": sources,
        "error": abuseipdb.get("error") or spamhaus.get("error"),
    }
    if redis is not None:
        try:
            await redis.setex(cache_key, settings.THREAT_INTEL_CACHE_TTL_SECONDS, json.dumps(result))
        except Exception:
            logger.warning("Redis unavailable for threat_intel cache write (ip=%s)", ip)
    return result


def _attack_surface_level(score: int) -> str:
    if score >= 70:
        return "CRITICAL"
    if score >= 45:
        return "HIGH"
    if score >= 20:
        return "MEDIUM"
    return "LOW"


def _attack_path_node(
    node_id: str,
    label: str,
    node_type: str,
    severity: str = "medium",
    port: int | None = None,
    detail: str | None = None,
) -> dict:
    return {
        "id": node_id,
        "label": label,
        "type": node_type,
        "severity": severity,
        "port": port,
        "detail": detail,
    }


def _attack_path_edge(source: str, target: str, label: str, severity: str = "medium") -> dict:
    return {
        "source": source,
        "target": target,
        "label": label,
        "severity": severity,
    }


def _best_web_label(port: OpenPortDetail) -> str:
    techs = [tech for tech in port.technologies if tech]
    if port.version:
        return port.version.split()[0].split("/")[0].upper()
    if techs:
        return techs[0]
    return port.service or "Web Service"


def _best_port_by_score(ports: list[OpenPortDetail]) -> OpenPortDetail | None:
    if not ports:
        return None
    return max(
        ports,
        key=lambda port: (
            int(port.exposure_severity.get("score") or 0),
            port.cve_critical_count,
            port.cve_high_count,
            port.cve_count,
        ),
    )


def _path_summary(nodes_by_id: dict[str, dict], steps: list[str]) -> str:
    labels = []
    for step in steps:
        node = nodes_by_id.get(step)
        if node and node.get("label"):
            labels.append(str(node["label"]))
    return " → ".join(labels)


def build_attack_path_visualization(
    open_ports: list[OpenPortDetail],
    exposure_summary: dict | None = None,
) -> dict:
    """Build inferred attack paths from exposed services for frontend visualization."""
    if not open_ports:
        return {
            "nodes": [],
            "edges": [],
            "paths": [],
            "summary": "No attack path could be inferred because no open ports were found.",
        }

    public_exposure = bool((exposure_summary or {}).get("public_exposure"))
    web_ports = [p for p in open_ports if p.port_number in HTTP_PORTS]
    admin_ports = [p for p in open_ports if p.port_number in ADMIN_SERVICE_PORTS or p.port_number in REMOTE_ACCESS_PORTS]
    database_ports = [p for p in open_ports if p.port_number in DATABASE_PORTS]
    vulnerable_ports = [
        p for p in open_ports
        if p.cve_critical_count or p.cve_high_count or p.exploit_availability.get("public_exploit_available") is True
    ]

    entry = _attack_path_node(
        "internet",
        "Internet (public IP)" if public_exposure else "Scanner Network",
        "entry",
        "critical" if public_exposure else "medium",
        detail="Target resolved to a public IP address" if public_exposure else "Target is reachable from the scanner network",
    )
    nodes_by_id = {entry["id"]: entry}
    edges: list[dict] = []
    paths: list[dict] = []

    def add_node(node: dict) -> None:
        nodes_by_id[node["id"]] = node

    def add_edge(edge: dict) -> None:
        if edge not in edges:
            edges.append(edge)

    primary_web = _best_port_by_score(web_ports)
    primary_admin = _best_port_by_score(admin_ports)
    primary_db = _best_port_by_score(database_ports)
    primary_vuln = _best_port_by_score(vulnerable_ports)

    if primary_web:
        web_id = f"web-{primary_web.port_number}"
        web_label = _best_web_label(primary_web)
        add_node(_attack_path_node(
            web_id,
            web_label,
            "web",
            primary_web.risk_level,
            primary_web.port_number,
            primary_web.version or primary_web.service,
        ))
        add_edge(_attack_path_edge(
            "internet",
            web_id,
            f"HTTP/S exposed on {primary_web.port_number}",
            primary_web.risk_level,
        ))

        previous_id = web_id
        steps = ["internet", web_id]

        if primary_web.misconfigurations or primary_web.cve_count or primary_web.exploit_availability.get("public_exploit_available"):
            app_id = "admin-panel"
            reasons = []
            if primary_web.misconfigurations:
                reasons.append("observed web misconfiguration")
            if primary_web.cve_count:
                reasons.append(f"{primary_web.cve_count} CVE signal(s)")
            if primary_web.exploit_availability.get("public_exploit_available"):
                reasons.append("curated public-exploit signal")
            add_node(_attack_path_node(
                app_id,
                "Inferred Admin Surface",
                "application",
                "high" if primary_web.risk_level != "critical" else "critical",
                detail=", ".join(reasons) or "Inferred from exposed web service",
            ))
            add_edge(_attack_path_edge(
                previous_id,
                app_id,
                "Potential web-to-admin pivot",
                "high",
            ))
            previous_id = app_id
            steps.append(app_id)

        if primary_db:
            db_id = f"db-{primary_db.port_number}"
            add_node(_attack_path_node(
                db_id,
                primary_db.service or "Database",
                "database",
                primary_db.risk_level,
                primary_db.port_number,
                primary_db.version or "Exposed database service",
            ))
            add_edge(_attack_path_edge(
                previous_id,
                db_id,
                "Potential backend data-service pivot",
                "critical" if primary_db.risk_level == "critical" else "high",
            ))
            steps.append(db_id)

        paths.append({
            "id": "web-to-data",
            "title": "Web-to-Data Attack Path",
            "severity": "critical" if primary_db and public_exposure else "high",
            "steps": steps,
            "summary": _path_summary(nodes_by_id, steps),
        })

    elif primary_admin:
        admin_id = f"admin-{primary_admin.port_number}"
        add_node(_attack_path_node(
            admin_id,
            primary_admin.service or "Admin Service",
            "admin",
            primary_admin.risk_level,
            primary_admin.port_number,
            primary_admin.exposure_severity.get("finding") or primary_admin.service_security_concern,
        ))
        add_edge(_attack_path_edge(
            "internet",
            admin_id,
            "Direct remote-access exposure",
            primary_admin.risk_level,
        ))
        paths.append({
            "id": "direct-admin",
            "title": "Direct Admin Access Path",
            "severity": primary_admin.risk_level,
            "steps": ["internet", admin_id],
            "summary": _path_summary(nodes_by_id, ["internet", admin_id]),
        })

    if primary_vuln and (not primary_web or primary_vuln.port_number != primary_web.port_number):
        vuln_id = f"vuln-{primary_vuln.port_number}"
        add_node(_attack_path_node(
            vuln_id,
            primary_vuln.service or "Vulnerable Service",
            "vulnerability",
            "critical" if primary_vuln.cve_critical_count else "high",
            primary_vuln.port_number,
            primary_vuln.max_cvss_cve or "Public exploit or high-impact CVE signal",
        ))
        add_edge(_attack_path_edge(
            "internet",
            vuln_id,
            "Potential exploit path from exposed service",
            "critical" if primary_vuln.cve_critical_count else "high",
        ))
        paths.append({
            "id": "exploit-service",
            "title": "Exploit-to-Service Path",
            "severity": "critical" if primary_vuln.cve_critical_count else "high",
            "steps": ["internet", vuln_id],
            "summary": _path_summary(nodes_by_id, ["internet", vuln_id]),
        })

    if not paths:
        safest = _best_port_by_score(open_ports)
        if safest:
            service_id = f"service-{safest.port_number}"
            add_node(_attack_path_node(
                service_id,
                safest.service or "Open Service",
                "service",
                safest.risk_level,
                safest.port_number,
                safest.service_security_concern,
            ))
            add_edge(_attack_path_edge("internet", service_id, "Reachable open service observed", safest.risk_level))
            paths.append({
                "id": "reachable-service",
                "title": "Reachable Service Path",
                "severity": safest.risk_level,
                "steps": ["internet", service_id],
                "summary": _path_summary(nodes_by_id, ["internet", service_id]),
            })

    highest_path = max(
        paths,
        key=lambda path: EXPOSURE_SEVERITY_RANK.get(str(path.get("severity", "medium")).lower(), 2),
    ) if paths else None

    return {
        "nodes": list(nodes_by_id.values()),
        "edges": edges,
        "paths": paths,
        "summary": highest_path["summary"] if highest_path else "No attack path inferred.",
        "highest_severity": highest_path["severity"] if highest_path else "low",
    }


def _simulation(
    chain_id: str,
    title: str,
    severity: str,
    steps: list[str],
    likelihood: str,
    recommendation: str,
    evidence: list[str],
    confidence: str = "Inferred",
) -> dict:
    return {
        "id": chain_id,
        "title": title,
        "severity": severity,
        "steps": steps,
        "chain": " → ".join(steps),
        "likelihood": likelihood,
        "recommendation": recommendation,
        "evidence": [item for item in evidence if item][:6],
        "confidence": confidence,
    }


def build_attack_simulation_recommendations(
    open_ports: list[OpenPortDetail],
    exposure_summary: dict | None = None,
) -> list[dict]:
    """Create defensive attack-chain simulations from observed exposure."""
    simulations: list[dict] = []
    public_exposure = bool((exposure_summary or {}).get("public_exposure"))

    for port in open_ports:
        service = port.service or f"TCP/{port.port_number}"
        evidence = [
            f"Port {port.port_number} open",
            port.exposure_severity.get("finding"),
            port.risk_reason,
        ]

        if port.port_number == 22:
            simulations.append(_simulation(
                "ssh-credential-access",
                "SSH Credential Attack Simulation",
                "critical" if public_exposure else "high",
                ["Open SSH", "Credential Attack Risk", "Potential Server Access"],
                "Elevated" if public_exposure else "Moderate",
                "Run an authorized password-policy audit, disable password login where possible, enforce MFA, and restrict SSH to VPN or trusted IPs.",
                evidence + ["Remote login service observed", "Credential attack risk inferred from exposed SSH"],
            ))
        elif port.port_number == 3389:
            simulations.append(_simulation(
                "rdp-credential-access",
                "RDP Remote Access Simulation",
                "critical",
                ["Open RDP", "Credential Attack Risk", "Potential Interactive Access"],
                "Elevated" if public_exposure else "Moderate",
                "Place RDP behind VPN or zero-trust access, require MFA, lock out brute-force attempts, and monitor successful remote logons.",
                evidence + ["Remote desktop service observed"],
            ))
        elif port.port_number == 23:
            simulations.append(_simulation(
                "telnet-cleartext-access",
                "Telnet Credential Exposure Simulation",
                "critical",
                ["Open Telnet", "Cleartext Credential Exposure", "Potential Server Access"],
                "Elevated",
                "Disable Telnet and replace it with SSH over a restricted management network.",
                evidence + ["Cleartext authentication risk is inherent to Telnet"],
            ))
        elif port.port_number in HTTP_PORTS:
            web_steps = [f"Open {service}", "Web Reconnaissance"]
            if port.misconfigurations:
                web_steps.append("Observed Misconfiguration Review")
            elif port.cve_count:
                web_steps.append("Known Vulnerability Validation")
            else:
                web_steps.append("Administrative Route Discovery")
            web_steps.append("Potential Application Access")
            simulations.append(_simulation(
                f"web-{port.port_number}-application-access",
                "Web Application Attack Simulation",
                "critical" if port.cve_critical_count else ("high" if port.misconfigurations or port.cve_count else "medium"),
                web_steps,
                "Elevated" if public_exposure and (port.misconfigurations or port.cve_count) else "Moderate",
                "Validate authentication, patch the web stack, remove exposed admin routes, and fix reported web misconfigurations.",
                evidence + [
                    f"{len(port.misconfigurations)} misconfiguration(s)" if port.misconfigurations else None,
                    f"{port.cve_count} CVE signal(s)" if port.cve_count else None,
                ],
            ))
        elif port.port_number in DATABASE_PORTS:
            simulations.append(_simulation(
                f"db-{port.port_number}-data-access",
                "Database Exposure Simulation",
                "critical" if public_exposure else "high",
                [f"Open {service}", "Credential Reuse Risk", "Potential Data Access"],
                "Elevated" if public_exposure else "Moderate",
                "Bind the database to private interfaces, restrict source networks, rotate exposed credentials, and alert on direct database logins.",
                evidence + ["Database service observed"],
            ))
        elif port.port_number == 445:
            simulations.append(_simulation(
                "smb-lateral-movement",
                "SMB Lateral Movement Simulation",
                "critical" if public_exposure else "high",
                ["Open SMB", "Share Enumeration Risk", "Potential Lateral Movement"],
                "Elevated" if public_exposure else "Moderate",
                "Block SMB from untrusted networks, audit shares, disable guest access, and require SMB signing.",
                evidence + ["SMB service observed"],
            ))

    vulnerable = _best_port_by_score([
        p for p in open_ports
        if p.exploit_availability.get("public_exploit_available") is True or p.cve_critical_count
    ])
    if vulnerable:
        simulations.append(_simulation(
            f"exploit-{vulnerable.port_number}-server-access",
            "Curated Exploit-Signal Simulation",
            "critical",
            [f"Open {vulnerable.service}", "Curated Public-Exploit Signal", "Potential Server Access"],
            "Elevated",
            "Prioritize patching this service, confirm compensating controls, and run only authorized exploit validation in a controlled test window.",
            [
                f"Port {vulnerable.port_number} open",
                vulnerable.max_cvss_cve,
                "Curated public-exploit signal" if vulnerable.exploit_availability.get("public_exploit_available") is True else None,
            ],
        ))

    rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    deduped = {}
    for item in simulations:
        deduped[item["id"]] = item
    return sorted(
        deduped.values(),
        key=lambda item: (rank.get(item["severity"], 2), item["likelihood"] == "Elevated"),
        reverse=True,
    )[:8]


def calculate_attack_surface(open_ports: list[OpenPortDetail]) -> dict:
    public_services = []
    factors: list[dict] = []
    seen_services = set()

    for port in open_ports:
        service = port.service or "Unknown"
        if service not in seen_services:
            seen_services.add(service)
            public_services.append({
                "port": port.port_number,
                "service": service,
                "risk_level": port.risk_level,
            })

        if port.risk_level in {"critical", "high"}:
            factors.append(_surface_factor(
                "risky_services",
                f"{service} on port {port.port_number} is classified as {port.risk_level} risk.",
                16 if port.risk_level == "critical" else 11,
                port.risk_level,
            ))
        elif port.risk_level == "medium":
            factors.append(_surface_factor(
                "risky_services",
                f"{service} on port {port.port_number} adds moderate exposure.",
                5,
                "medium",
            ))

        if port.port_number in EXPOSED_SERVICE_PORTS:
            factors.append(_surface_factor(
                "exposed_services",
                f"{service} is publicly exposed: {EXPOSED_SERVICE_PORTS[port.port_number]}",
                10,
                "high",
            ))

        if port.port_number in ADMIN_SERVICE_PORTS:
            factors.append(_surface_factor(
                "admin_services",
                f"Administrative or remote-access service {service} is exposed on port {port.port_number}.",
                12,
                "high",
            ))

        if port.cve_critical_count or port.cve_high_count:
            factors.append(_surface_factor(
                "outdated_versions",
                f"{service} on port {port.port_number} has high-impact vulnerability signals.",
                15 if port.cve_critical_count else 9,
                "critical" if port.cve_critical_count else "high",
            ))
        elif port.cve_count:
            factors.append(_surface_factor(
                "outdated_versions",
                f"{service} on port {port.port_number} has known vulnerability signals.",
                5,
                "medium",
            ))

    port_count = len(open_ports)
    if port_count >= 20:
        factors.append(_surface_factor("open_port_count", f"{port_count} open ports create a broad attack surface.", 18, "high"))
    elif port_count >= 8:
        factors.append(_surface_factor("open_port_count", f"{port_count} open ports create a moderate attack surface.", 10, "medium"))
    elif port_count >= 4:
        factors.append(_surface_factor("open_port_count", f"{port_count} open ports increase reachable service exposure.", 5, "medium"))

    score = min(100, sum(int(f["weight"]) for f in factors))
    level = _attack_surface_level(score)
    return {
        "level": level,
        "score": score,
        "publicly_exposed_services": public_services,
        "factors": factors[:12],
        "summary": (
            f"{level} attack surface based on {port_count} open port(s), "
            f"{sum(1 for p in open_ports if p.port_number in ADMIN_SERVICE_PORTS)} admin service(s), "
            f"and {sum(1 for p in open_ports if p.cve_count)} service(s) with vulnerability signals."
        ),
    }


def _mitre_url(technique_id: str) -> str:
    path = technique_id.replace(".", "/")
    return f"https://attack.mitre.org/techniques/{path}/"


def add_mitre_attack_mapping(open_ports: list[OpenPortDetail]) -> None:
    """Attach local MITRE ATT&CK mappings and potential threat summaries."""
    for port in open_ports:
        service_key = (port.service or "").lower()
        mapped = list(MITRE_PORT_MAPPINGS.get(port.port_number, []))
        mapped.extend(MITRE_SERVICE_MAPPINGS.get(service_key, []))

        seen = set()
        techniques = []
        for technique_id, name, tactic in mapped:
            if technique_id in seen:
                continue
            seen.add(technique_id)
            techniques.append({
                "technique_id": technique_id,
                "technique_name": name,
                "tactic": tactic,
                "url": _mitre_url(technique_id),
                "attack_vector": f"{port.service} exposure on TCP/{port.port_number}",
                "threat_behavior": name,
            })

        port.mitre_attack = techniques
        port.potential_threat = POTENTIAL_THREATS.get(
            port.port_number,
            f"Reconnaissance or exploitation attempts may be possible against {port.service} on port {port.port_number}.",
        ) if techniques else None


async def calculate_security_score(
    target: str,
    open_ports: list[OpenPortDetail],
    ssl_cache: dict[int, SSLResult] | None = None,
) -> tuple[int, list[dict]]:
    """Calculate a simple defensive exposure score from scan findings."""
    factors: list[dict] = []

    for port in open_ports:
        if port.risk_level == "critical":
            factors.append(_score_factor("risky_ports", f"Critical-risk port {port.port_number} ({port.service}) is open.", 18, "critical"))
        elif port.risk_level == "high":
            factors.append(_score_factor("risky_ports", f"High-risk port {port.port_number} ({port.service}) is open.", 12, "high"))
        elif port.risk_level == "medium":
            factors.append(_score_factor("risky_ports", f"Medium-risk port {port.port_number} ({port.service}) is open.", 5, "medium"))

        if port.port_number in EXPOSED_SERVICE_PORTS:
            factors.append(_score_factor(
                "exposed_services",
                f"Exposed service on port {port.port_number}: {EXPOSED_SERVICE_PORTS[port.port_number]}",
                10,
                "high",
            ))

        if port.cve_critical_count:
            factors.append(_score_factor(
                "outdated_versions",
                f"Port {port.port_number} has {port.cve_critical_count} critical CVE signal(s).",
                min(20, port.cve_critical_count * 10),
                "critical",
            ))
        if port.cve_high_count:
            factors.append(_score_factor(
                "outdated_versions",
                f"Port {port.port_number} has {port.cve_high_count} high-severity CVE signal(s).",
                min(15, port.cve_high_count * 6),
                "high",
            ))
        elif port.cve_count:
            factors.append(_score_factor(
                "outdated_versions",
                f"Port {port.port_number} has known vulnerability signals for its detected version.",
                min(8, port.cve_count * 2),
                "medium",
            ))

    ssl_ports = [p for p in open_ports if p.port_number in HTTPS_PORTS]
    if ssl_ports:
        if ssl_cache:
            ssl_results: list[SSLResult | Exception] = [
                ssl_cache.get(p.port_number, Exception("not in cache")) for p in ssl_ports
            ]
        else:
            ssl_results = await asyncio.gather(
                *(ssl_audit(target, p.port_number) for p in ssl_ports),
                return_exceptions=True,
            )
        for port, result in zip(ssl_ports, ssl_results):
            if isinstance(result, Exception):
                factors.append(_score_factor("weak_ssl", f"TLS audit failed on port {port.port_number}.", 5, "medium"))
                continue
            if result.error:
                factors.append(_score_factor("weak_ssl", f"TLS issue on port {port.port_number}: {result.error}", 6, "medium"))
                continue
            if result.cert and result.cert.is_expired:
                factors.append(_score_factor("weak_ssl", f"Expired TLS certificate on port {port.port_number}.", 14, "high"))
            elif result.cert and result.cert.days_remaining < 14:
                factors.append(_score_factor("weak_ssl", f"TLS certificate on port {port.port_number} expires soon.", 5, "medium"))
            if result.is_self_signed:
                factors.append(_score_factor("weak_ssl", f"Self-signed TLS certificate on port {port.port_number}.", 8, "medium"))
            if not result.supports_tls12:
                factors.append(_score_factor("weak_ssl", f"Port {port.port_number} does not support TLS 1.2.", 10, "high"))
            if result.tls_version and result.tls_version in {"TLSv1", "TLSv1.1"}:
                factors.append(_score_factor("weak_ssl", f"Port {port.port_number} negotiated outdated {result.tls_version}.", 12, "high"))

    total_penalty = min(100, sum(int(f.get("penalty", 0)) for f in factors))
    return max(0, 100 - total_penalty), factors[:12]


async def check_port(
    target: str,
    port: int,
    timeout: float = 2.0,
    hostname: str | None = None,
) -> OpenPortDetail | None:
    """Check if a port is open, grab banners, and detect service version."""
    host_header = hostname or target
    try:
        if port in HTTPS_PORTS:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port, ssl=_ssl_context()),
                timeout=timeout,
            )
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port),
                timeout=timeout,
            )
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return None
    except Exception:
        return None

    service = get_service_for_port(port)
    risk_level, risk_reason = classify_port_risk(port, service)
    port_desc = get_port_description(port, service)
    detail = OpenPortDetail(
        port_number=port,
        service=service,
        status="open",
        risk_level=risk_level,
        risk_reason=risk_reason,
        service_description=port_desc.purpose,
        service_security_concern=port_desc.security_concern,
    )
    probe_timeout = _probe_timeout(port, timeout)
    raw_bytes = b""

    try:
        if port in HTTP_PORTS:
            banner = await grab_http_banner(reader, writer, host_header, probe_timeout)
            _apply_banner(detail, banner)
            raw_bytes = (banner.raw_banner or "").encode("utf-8", errors="replace")
            detail.version = parse_http_response(raw_bytes) if raw_bytes else None
            detail.technologies = detect_technologies(raw_bytes)
        elif port in WELCOME_PORTS:
            raw_bytes = await read_passive_banner(reader, probe_timeout)
            banner = from_bytes(raw_bytes)
            _apply_banner(detail, banner)
            detail.version = _version_from_banner(port, raw_bytes, http=False)
            detail.technologies = detect_technologies(raw_bytes)
        else:
            raw_bytes = await read_passive_banner(reader, min(probe_timeout, 1.5))
            if raw_bytes:
                banner = from_bytes(raw_bytes)
                _apply_banner(detail, banner)
                detail.technologies = detect_technologies(raw_bytes)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    return detail


async def scan_ports(
    target: str,
    ports: List[int] | None = None,
    timeout: float = 2.0,
    max_concurrent: int = 100,
    allow_private: bool = False,
    db_session: Optional[AsyncSession] = None,
    include_ai_recommendations: bool = True,
    include_threat_intel: bool = True,
    include_misconfigurations: bool = True,
    include_screenshots: bool = True,
) -> PortScanResult:
    """
    Scan multiple ports on a target host concurrently.
    
    Args:
        target: Target hostname or IP address
        ports: List of ports to scan (defaults to common ports)
        timeout: Connection timeout per port in seconds
        max_concurrent: Maximum concurrent connections
    
    Returns:
        PortScanResult with scan details
    """
    start_time = time.time()
    
    # Default to common ports if none specified
    if ports is None:
        ports = list(COMMON_PORTS.keys())
    
    # Resolve target to IP
    try:
        loop = asyncio.get_running_loop()
        ip = (await loop.getaddrinfo(target, None, family=socket.AF_INET))[0][4][0]
    except Exception as e:
        return PortScanResult(
            target=target,
            total_scanned=0,
            open_ports_count=0,
            open_ports=[],
            detected_technologies=[],
            scan_duration_seconds=0.0,
            packets_sent=0,
            avg_latency_ms=None,
            security_score=0,
            security_score_factors=[
                _score_factor("scan_error", "DNS resolution failed, so the target could not be scored.", 100, "critical")
            ],
            attack_surface={
                "level": "UNKNOWN",
                "score": 0,
                "publicly_exposed_services": [],
                "factors": [],
                "summary": "DNS resolution failed, so attack surface could not be calculated.",
            },
            threat_intelligence=_empty_threat_intel(None, "Unknown", "DNS resolution failed, so reputation could not be checked."),
            misconfiguration_summary=_misconfiguration_summary([]),
            exposure_summary={
                "public_exposure": False,
                "highest_severity": "unknown",
                "highest_score": 0,
                "highest_finding": "DNS resolution failed, so exposure severity could not be calculated.",
                "highest_port": None,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
            },
            attack_paths={
                "nodes": [],
                "edges": [],
                "paths": [],
                "summary": "DNS resolution failed, so attack paths could not be inferred.",
                "highest_severity": "unknown",
            },
            attack_simulations=[],
            recommendations_error=None,
            error=f"DNS resolution failed: {e}"
        )

    # Block scans against private / loopback / cloud-metadata targets unless
    # the caller has explicitly opted in (authenticated internal use only).
    if not allow_private and not _is_scan_target_allowed(ip):
        return PortScanResult(
            target=target,
            total_scanned=0,
            open_ports_count=0,
            open_ports=[],
            detected_technologies=[],
            scan_duration_seconds=0.0,
            packets_sent=0,
            avg_latency_ms=None,
            security_score=0,
            security_score_factors=[
                _score_factor("scan_error", _BLOCKED_SCAN_ERROR, 100, "critical")
            ],
            attack_surface={
                "level": "UNKNOWN",
                "score": 0,
                "publicly_exposed_services": [],
                "factors": [],
                "summary": _BLOCKED_SCAN_ERROR,
            },
            threat_intelligence=_empty_threat_intel(ip, "Unknown", _BLOCKED_SCAN_ERROR),
            misconfiguration_summary=_misconfiguration_summary([]),
            exposure_summary={
                "public_exposure": False,
                "highest_severity": "unknown",
                "highest_score": 0,
                "highest_finding": _BLOCKED_SCAN_ERROR,
                "highest_port": None,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
            },
            attack_paths={
                "nodes": [],
                "edges": [],
                "paths": [],
                "summary": _BLOCKED_SCAN_ERROR,
                "highest_severity": "unknown",
            },
            attack_simulations=[],
            recommendations_error=None,
            error=_BLOCKED_SCAN_ERROR,
        )

    # Create semaphore to limit concurrent connections
    semaphore = asyncio.Semaphore(max_concurrent)
    attempt_latencies_ms: list[float] = []

    async def scan_with_semaphore(port: int) -> OpenPortDetail | None:
        async with semaphore:
            attempt_start = time.perf_counter()
            try:
                return await check_port(ip, port, timeout, hostname=target)
            finally:
                attempt_latencies_ms.append((time.perf_counter() - attempt_start) * 1000)
    
    # Scan all ports concurrently
    tasks = [scan_with_semaphore(port) for port in ports]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    # Filter successful results
    open_ports = []
    for result in results:
        if isinstance(result, OpenPortDetail):
            open_ports.append(result)
    
    scan_duration = time.time() - start_time
    avg_latency_ms = (
        sum(attempt_latencies_ms) / len(attempt_latencies_ms)
        if attempt_latencies_ms
        else None
    )
    all_technologies = merge_technologies(*(p.technologies for p in open_ports))
    add_service_fingerprints(open_ports)

    # Run ssl_audit once per HTTPS port upfront so both detect_misconfigurations
    # and calculate_security_score share the same results without duplicate calls.
    https_ports_list = [p for p in open_ports if p.port_number in HTTPS_PORTS]
    if https_ports_list:
        _ssl_results = await asyncio.gather(
            *(ssl_audit(target, p.port_number, allow_private=allow_private) for p in https_ports_list),
            return_exceptions=True,
        )
        ssl_cache: dict[int, SSLResult] = {
            p.port_number: r
            for p, r in zip(https_ports_list, _ssl_results)
            if not isinstance(r, Exception)
        }
    else:
        ssl_cache = {}

    # Run the four independent analysis steps concurrently.
    # and check_threat_intelligence do not depend on each other's output.
    version_strings = [p.version for p in open_ports if p.version]

    async def _run_cves() -> dict:
        if not version_strings:
            return {}
        return await detect_cves_batch(version_strings, db_session)

    async def _empty_threat_intel_coro():
        return _empty_threat_intel(ip, "Not checked", "Threat intelligence check was skipped for this scan.")

    async def _empty_misconfig_coro():
        return _misconfiguration_summary([])

    _threat_intel_coro = (
        check_threat_intelligence(ip)
        if include_threat_intel
        else _empty_threat_intel_coro()
    )
    _misconfig_coro = (
        detect_misconfigurations(target, open_ports, timeout, ssl_cache, allow_private=allow_private)
        if include_misconfigurations
        else _empty_misconfig_coro()
    )
    _screenshot_coro = (
        capture_web_port_screenshots(target, open_ports)
        if include_screenshots
        else asyncio.sleep(0)
    )
    cve_results, misconfiguration_summary, _, threat_intelligence = await asyncio.gather(
        _run_cves(),
        _misconfig_coro,
        _screenshot_coro,
        _threat_intel_coro,
    )

    # Attach CVE results to ports (must happen before add_exploit_availability).
    for port in open_ports:
        if port.version and port.version in cve_results:
            port.cve_result = cve_results[port.version]
            port.cve_count = port.cve_result.total_count
            port.cve_critical_count = port.cve_result.critical_count
            port.cve_high_count = port.cve_result.high_count
            port.cve_medium_count = port.cve_result.medium_count
            port.cve_low_count = port.cve_result.low_count
            scored_cves = [
                cve for cve in port.cve_result.cves
                if cve.cvss_score is not None
            ]
            if scored_cves:
                top_cve = max(scored_cves, key=lambda cve: float(cve.cvss_score or 0))
                port.max_cvss_score = float(top_cve.cvss_score)
                port.max_cvss_severity = top_cve.severity
                port.max_cvss_cve = top_cve.cve_id

    add_exploit_availability(open_ports)

    exposure_summary = calculate_exposure_severity(ip, open_ports, threat_intelligence)
    attack_paths = build_attack_path_visualization(open_ports, exposure_summary)
    attack_simulations = build_attack_simulation_recommendations(open_ports, exposure_summary)
    add_mitre_attack_mapping(open_ports)
    security_score, security_score_factors = await calculate_security_score(target, open_ports, ssl_cache)
    attack_surface = calculate_attack_surface(open_ports)
    recommendations_error = await add_ai_recommendations(target, open_ports) if include_ai_recommendations else None

    return PortScanResult(
        target=target,
        total_scanned=len(ports),
        open_ports_count=len(open_ports),
        open_ports=open_ports,
        detected_technologies=all_technologies,
        scan_duration_seconds=scan_duration,
        packets_sent=len(ports),
        avg_latency_ms=avg_latency_ms,
        security_score=security_score,
        security_score_factors=security_score_factors,
        attack_surface=attack_surface,
        threat_intelligence=threat_intelligence,
        misconfiguration_summary=misconfiguration_summary,
        exposure_summary=exposure_summary,
        attack_paths=attack_paths,
        attack_simulations=attack_simulations,
        recommendations_error=recommendations_error,
        error=None
    )


async def stream_port_scan_events(
    target: str,
    ports: List[int] | None = None,
    timeout: float = 2.0,
    max_concurrent: int = 100,
    allow_private: bool = False,
    db_session: Optional[AsyncSession] = None,
    include_ai_recommendations: bool = True,
    include_threat_intel: bool = True,
    include_misconfigurations: bool = True,
    include_screenshots: bool = True,
):
    """Yield port scan events as individual port checks complete."""
    start_time = time.time()

    if ports is None:
        ports = list(COMMON_PORTS.keys())

    yield {
        "type": "init",
        "data": {
            "target": target,
            "total_scanned": len(ports),
            "open_ports_count": 0,
            "open_ports": [],
            "scan_duration_seconds": 0.0,
            "packets_sent": 0,
            "avg_latency_ms": None,
            "scanning": True,
        },
    }

    try:
        loop = asyncio.get_running_loop()
        ip = (await loop.getaddrinfo(target, None, family=socket.AF_INET))[0][4][0]
    except Exception as e:
        yield {"type": "error", "error": f"DNS resolution failed: {e}"}
        return

    # Block scans against private / loopback / cloud-metadata targets unless
    # the caller has explicitly opted in (authenticated internal use only).
    if not allow_private and not _is_scan_target_allowed(ip):
        yield {"type": "error", "error": _BLOCKED_SCAN_ERROR}
        return

    semaphore = asyncio.Semaphore(max_concurrent)
    attempt_latencies_ms: list[float] = []
    open_ports: list[OpenPortDetail] = []

    async def scan_with_semaphore(port: int) -> tuple[int, OpenPortDetail | None, float]:
        async with semaphore:
            attempt_start = time.perf_counter()
            detail = await check_port(ip, port, timeout, hostname=target)
            elapsed_ms = (time.perf_counter() - attempt_start) * 1000
            attempt_latencies_ms.append(elapsed_ms)
            return port, detail, elapsed_ms

    tasks = [asyncio.create_task(scan_with_semaphore(port)) for port in ports]
    checked_count = 0
    for task in asyncio.as_completed(tasks):
        port, detail, elapsed_ms = await task
        checked_count += 1
        if detail:
            open_ports.append(detail)
            yield {
                "type": "port",
                "port": asdict(detail),
                "progress": {
                    "checked": checked_count,
                    "total": len(ports),
                    "open": len(open_ports),
                    "last_port": port,
                    "latency_ms": round(elapsed_ms, 2),
                },
            }
        else:
            yield {
                "type": "progress",
                "progress": {
                    "checked": checked_count,
                    "total": len(ports),
                    "open": len(open_ports),
                    "last_port": port,
                    "latency_ms": round(elapsed_ms, 2),
                },
            }

    avg_latency_ms = (
        sum(attempt_latencies_ms) / len(attempt_latencies_ms)
        if attempt_latencies_ms
        else None
    )
    add_service_fingerprints(open_ports)

    # Run ssl_audit once per HTTPS port upfront so both detect_misconfigurations
    # and calculate_security_score share the same results without duplicate calls.
    https_ports_list = [p for p in open_ports if p.port_number in HTTPS_PORTS]
    if https_ports_list:
        _ssl_results = await asyncio.gather(
            *(ssl_audit(target, p.port_number, allow_private=allow_private) for p in https_ports_list),
            return_exceptions=True,
        )
        ssl_cache: dict[int, SSLResult] = {
            p.port_number: r
            for p, r in zip(https_ports_list, _ssl_results)
            if not isinstance(r, Exception)
        }
    else:
        ssl_cache = {}

    # Run the four independent analysis steps concurrently.
    # and check_threat_intelligence do not depend on each other's output.
    version_strings = [p.version for p in open_ports if p.version]

    async def _run_cves() -> dict:
        if not version_strings:
            return {}
        return await detect_cves_batch(version_strings, db_session)

    async def _empty_threat_intel_coro():
        return _empty_threat_intel(ip, "Not checked", "Threat intelligence check was skipped for this scan.")

    async def _empty_misconfig_coro():
        return _misconfiguration_summary([])

    _threat_intel_coro = (
        check_threat_intelligence(ip)
        if include_threat_intel
        else _empty_threat_intel_coro()
    )
    _misconfig_coro = (
        detect_misconfigurations(target, open_ports, timeout, ssl_cache, allow_private=allow_private)
        if include_misconfigurations
        else _empty_misconfig_coro()
    )
    _screenshot_coro = (
        capture_web_port_screenshots(target, open_ports)
        if include_screenshots
        else asyncio.sleep(0)
    )
    cve_results, misconfiguration_summary, _, threat_intelligence = await asyncio.gather(
        _run_cves(),
        _misconfig_coro,
        _screenshot_coro,
        _threat_intel_coro,
    )

    # Attach CVE results to ports (must happen before add_exploit_availability).
    for port in open_ports:
        if port.version and port.version in cve_results:
            port.cve_result = cve_results[port.version]
            port.cve_count = port.cve_result.total_count
            port.cve_critical_count = port.cve_result.critical_count
            port.cve_high_count = port.cve_result.high_count
            port.cve_medium_count = port.cve_result.medium_count
            port.cve_low_count = port.cve_result.low_count
            scored_cves = [
                cve for cve in port.cve_result.cves
                if cve.cvss_score is not None
            ]
            if scored_cves:
                top_cve = max(scored_cves, key=lambda cve: float(cve.cvss_score or 0))
                port.max_cvss_score = float(top_cve.cvss_score)
                port.max_cvss_severity = top_cve.severity
                port.max_cvss_cve = top_cve.cve_id

    add_exploit_availability(open_ports)

    exposure_summary = calculate_exposure_severity(ip, open_ports, threat_intelligence)
    attack_paths = build_attack_path_visualization(open_ports, exposure_summary)
    attack_simulations = build_attack_simulation_recommendations(open_ports, exposure_summary)
    add_mitre_attack_mapping(open_ports)
    security_score, security_score_factors = await calculate_security_score(target, open_ports, ssl_cache)
    attack_surface = calculate_attack_surface(open_ports)
    recommendations_error = await add_ai_recommendations(target, open_ports) if include_ai_recommendations else None
    all_technologies = merge_technologies(*(p.technologies for p in open_ports))

    result = PortScanResult(
        target=target,
        total_scanned=len(ports),
        open_ports_count=len(open_ports),
        open_ports=open_ports,
        detected_technologies=all_technologies,
        scan_duration_seconds=time.time() - start_time,
        packets_sent=len(ports),
        avg_latency_ms=avg_latency_ms,
        security_score=security_score,
        security_score_factors=security_score_factors,
        attack_surface=attack_surface,
        threat_intelligence=threat_intelligence,
        misconfiguration_summary=misconfiguration_summary,
        exposure_summary=exposure_summary,
        attack_paths=attack_paths,
        attack_simulations=attack_simulations,
        recommendations_error=recommendations_error,
        error=None,
    )
    yield {"type": "done", "result": result}


async def scan_port_range(
    target: str,
    start_port: int = 1,
    end_port: int = 1024,
    timeout: float = 2.0,
    max_concurrent: int = 100,
    allow_private: bool = False,
    db_session: Optional[AsyncSession] = None,
    include_ai_recommendations: bool = True,
    include_threat_intel: bool = True,
    include_misconfigurations: bool = True,
    include_screenshots: bool = True,
) -> PortScanResult:
    """
    Scan a range of ports on a target host.
    """
    ports = list(range(start_port, end_port + 1))
    return await scan_ports(
        target, ports, timeout, max_concurrent,
        allow_private=allow_private, db_session=db_session,
        include_ai_recommendations=include_ai_recommendations,
        include_threat_intel=include_threat_intel,
        include_misconfigurations=include_misconfigurations,
        include_screenshots=include_screenshots,
    )
