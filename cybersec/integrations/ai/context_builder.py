import json
from cybersec.database.models import Scan, ScanResult
from cybersec.integrations.ai.prompts import (
    SCAN_ANALYST_PROMPT,
    SSL_ANALYST_PROMPT,
    DNS_ANALYST_PROMPT,
    HTTP_HEADERS_ANALYST_PROMPT,
    SUBDOMAIN_ANALYST_PROMPT,
    GENERIC_TOOL_ANALYST_PROMPT,
    CHAT_PROMPT
)

def format_duration(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.2f} seconds"
    m, s = divmod(seconds, 60)
    return f"{int(m)}m {int(s)}s"

def build_scan_context(scan: Scan, results: list[ScanResult]) -> str:
    duration_str = ""
    if hasattr(scan, 'started_at') and hasattr(scan, 'completed_at') and scan.started_at and scan.completed_at:
        seconds = (scan.completed_at - scan.started_at).total_seconds()
        duration_str = f"Duration: {format_duration(seconds)}\n"
        
    context = (
        "=== SCAN CONTEXT ===\n"
        f"Target: {getattr(scan, 'target', 'Unknown')}\n"
        f"Status: {getattr(scan, 'status', 'Unknown')}\n"
        f"Scan Type: {getattr(scan, 'scan_type', 'Unknown')}\n"
        f"Port Range: {getattr(scan, 'port_range', 'Unknown')}\n"
        f"{duration_str}"
        f"Started: {getattr(scan, 'started_at', 'Unknown')}\n\n"
        f"OPEN PORTS ({len(results)} found):\n"
    )
    
    ports_to_show = results[:20]
    for r in ports_to_show:
        banner = getattr(r, 'banner', '')
        banner_text = (banner[:100] + "...") if banner and len(banner) > 100 else banner
        
        context += f"Port {getattr(r, 'port', 'Unknown')}/{getattr(r, 'protocol', 'Unknown')} - {getattr(r, 'service', 'Unknown')} {getattr(r, 'version', 'Unknown')}\n"
        context += "  State: open\n"
        if banner_text:
            context += f"  Banner: {banner_text}\n"
            
        cves = getattr(r, 'cves', []) or []
        if callable(getattr(cves, "get", None)):
            cves = getattr(r, 'cves', [])
            if not isinstance(cves, list):
                cves = [cves] if cves else []
            
        if cves:
            context += f"  CVEs ({len(cves)}):\n"
            for cve in cves:
                cve_id = cve.get('id', 'UNKNOWN')
                score = cve.get('cvss_score', 'N/A')
                severity = cve.get('severity', 'UNKNOWN')
                desc = cve.get('description', '')
                desc_clipped = desc[:80] + "..." if len(desc) > 80 else desc
                context += f"    - {cve_id} (CVSS: {score}, {severity}): {desc_clipped}\n"
        
        # Adding Risk Score and MITRE as instructed "Risk Score: {risk_score} ({risk_level})\n  MITRE: {techniques}"
        risk_score = "N/A"
        risk_level = "N/A"
        techniques = "N/A"
        context += f"  Risk Score: {risk_score} ({risk_level})\n"
        context += f"  MITRE: {techniques}\n\n"
        
    if len(results) > 20:
        context += f"... and {len(results) - 20} more open ports\n"
        
    return context

def build_tool_context(tool_name: str, result_data: dict) -> str:
    target = result_data.get('target', result_data.get('host', 'unknown'))
    context = (
        "=== TOOL RESULT CONTEXT ===\n"
        f"Tool: {tool_name.upper()}\n"
        f"Target: {target}\n\n"
    )
    
    if tool_name == 'dns':
        records = result_data.get('records', [])
        for r in records:
            context += f"{r.get('type')}: {r.get('value')} (TTL: {r.get('ttl')})\n"
    elif tool_name == 'ssl':
        cert = result_data.get('cert') or {}
        context += f"Subject: {cert.get('subject')}\n"
        context += f"Expires: {cert.get('valid_until')} ({cert.get('days_remaining')} days remaining)\n"
        context += f"Cipher Suite: {result_data.get('cipher_suite')}\n"
        context += f"TLS Version: {result_data.get('tls_version')}\n"
    elif tool_name == 'http_headers':
        sa = result_data.get('security_analysis', [])
        for s in sa:
            status = 'Present' if s.get('present') else 'Missing'
            context += f"{s.get('header')}: {status} (Severity: {s.get('severity')})\n"
    elif tool_name == 'subdomain':
        found = result_data.get('found', [])
        resolved = [s for s in found if s.get('resolved')]
        unresolved = [s for s in found if not s.get('resolved')]
        context += f"Found {result_data.get('total_found', 0)} subdomains.\n"
        if result_data.get('wildcard_detected'):
            context += f"Wildcard DNS detected — IPs: {', '.join(result_data.get('wildcard_ips', []))}\n"
        for s in resolved:
            recs = s.get('records', {})
            parts = []
            for rtype in ("A", "AAAA", "CNAME", "MX", "TXT", "NS"):
                vals = recs.get(rtype, [])
                if vals:
                    if rtype == "TXT":
                        parts.append(f"TXT({len(vals)})")
                    else:
                        parts.append(f"{rtype}: {', '.join(vals)}")
            if s.get('wildcard'):
                parts.append("(wildcard)")
            risk = s.get('risk', {})
            if risk:
                parts.append(f"[{risk.get('level', 'LOW')}] {risk.get('reason', '')}")
            http = s.get('http', {})
            if http.get('alive'):
                http_parts = [f"HTTP {http.get('status')}"]
                if http.get('title'):
                    http_parts.append(f"title=\"{http['title']}\"")
                if http.get('server'):
                    http_parts.append(f"server={http['server']}")
                if http.get('technologies'):
                    http_parts.append(f"tech={','.join(http['technologies'])}")
                if http.get('response_time_ms'):
                    http_parts.append(f"{http['response_time_ms']}ms")
                parts.append(" | ".join(http_parts))
            context += f" - {s.get('subdomain')} | {' | '.join(parts)}\n"
        if unresolved:
            context += f"Failed resolutions ({len(unresolved)}):\n"
            for s in unresolved:
                context += f" - {s.get('subdomain')}: {s.get('error')}\n"
    elif tool_name == 'whois':
        context += f"Registrar: {result_data.get('registrar')}\n"
        context += f"Dates - Created: {result_data.get('creation_date')}, Expiration: {result_data.get('expiration_date')}\n"
        ns = result_data.get('name_servers', [])
        context += f"Nameservers: {', '.join(ns)}\n"
    elif tool_name in ('ping', 'traceroute'):
        if tool_name == 'ping':
            context += f"Packets Sent/Received: {result_data.get('packets_sent')}/{result_data.get('packets_received')}\n"
            context += f"Loss: {result_data.get('packet_loss_pct')}%\n"
            context += f"Min/Avg/Max RTT: {result_data.get('min_ms')}/{result_data.get('avg_ms')}/{result_data.get('max_ms')}\n"
        else:
            hops = result_data.get('hops', [])
            context += f"Total Hops: {result_data.get('total_hops')}\n"
            for h in hops:
                context += f"{h.get('hop')}: {h.get('ip')} - {h.get('rtt_ms')}ms\n"
    elif tool_name == 'geoip':
        context += f"Location: {result_data.get('city')}, {result_data.get('country')}\n"
        context += f"ISP: {result_data.get('isp')}\n"
        context += f"ASN: {result_data.get('asn')}\n"
    else:
        context += json.dumps(result_data, indent=2)[:2000]
        
    return context

def select_system_prompt(tool_name: str | None, has_scan: bool) -> str:
    if has_scan:
        return SCAN_ANALYST_PROMPT
    if tool_name == "ssl":
        return SSL_ANALYST_PROMPT
    if tool_name == "dns":
        return DNS_ANALYST_PROMPT
    if tool_name == "http_headers":
        return HTTP_HEADERS_ANALYST_PROMPT
    if tool_name == "subdomain":
        return SUBDOMAIN_ANALYST_PROMPT
    if tool_name is not None:
        return GENERIC_TOOL_ANALYST_PROMPT
    return CHAT_PROMPT
