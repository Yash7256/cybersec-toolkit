import logging

logger = logging.getLogger(__name__)


class ContextBuilder:
    def build_scan_context(self, scan: dict, results: list[dict]) -> str:
        if not scan:
            return ""

        target = scan.get("target", "Unknown")
        scan_type = scan.get("scan_type", "Unknown")
        status = scan.get("status", "Unknown")
        timestamp = scan.get("created_at", "Unknown")

        duration = scan.get("scan_duration")
        duration_str = f"{duration:.2f}s" if duration else "N/A"

        open_ports = [r for r in results if r.get("state") == "open"]
        open_count = len(open_ports)

        lines = [
            "=== SCAN ANALYSIS CONTEXT ===",
            f"TARGET: {target}",
            f"SCAN TYPE: {scan_type}",
            f"STATUS: {status}",
            f"SCAN DATE: {timestamp}",
            f"DURATION: {duration_str}",
            "",
            f"OPEN PORTS ({open_count}):",
        ]

        if open_ports:
            lines.append(f"{'PORT':<8} {'PROTOCOL':<10} {'SERVICE':<18} {'VERSION':<20} {'RISK':<8} {'TOP CVE'}")
            lines.append("-" * 100)

            os_hints = set()
            critical_count = 0
            high_cve_count = 0

            for port in open_ports:
                port_num = port.get("port", "")
                protocol = port.get("protocol", "")
                service = port.get("service", "unknown")
                version = port.get("version") or ""
                cves = port.get("cves") or []
                risk_score = port.get("risk_score", 0.0)

                top_cve = ""
                if cves:
                    sorted_cves = sorted(cves, key=lambda x: x.get("cvss_score", 0) if isinstance(x, dict) else 0, reverse=True)
                    if sorted_cves:
                        top_cve = sorted_cves[0].get("id", "") if isinstance(sorted_cves[0], dict) else ""
                        for cve in sorted_cves:
                            if isinstance(cve, dict):
                                score = cve.get("cvss_score", 0)
                                if score >= 7.0:
                                    high_cve_count += 1
                                    if score >= 9.0:
                                        critical_count += 1

                version_truncated = version[:18] if version else ""
                service_truncated = service[:16] if service else "unknown"
                lines.append(
                    f"{port_num:<8} {protocol:<10} {service_truncated:<18} {version_truncated:<20} {risk_score:<8.2f} {top_cve}"
                )

            if open_ports and any(p.get("os_hint") for p in open_ports):
                os_hints = {p.get("os_hint") for p in open_ports if p.get("os_hint")}
                lines.append("")
                lines.append(f"OS HINTS: {', '.join(os_hints)}")

            lines.append("")
            lines.append("SUMMARY:")

            if critical_count > 0:
                lines.append(f"- {critical_count} critical-risk ports found (CVSS >= 9.0)")
            if high_cve_count > 0:
                lines.append(f"- {high_cve_count} CVEs with CVSS >= 7.0")

            risk_categories = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for port in open_ports:
                risk = port.get("risk_score", 0)
                if risk >= 0.8:
                    risk_categories["critical"] += 1
                elif risk >= 0.6:
                    risk_categories["high"] += 1
                elif risk >= 0.3:
                    risk_categories["medium"] += 1
                else:
                    risk_categories["low"] += 1

            lines.append(f"- Risk distribution: {risk_categories['critical']} critical, "
                        f"{risk_categories['high']} high, {risk_categories['medium']} medium, "
                        f"{risk_categories['low']} low")
        else:
            lines.append("No open ports found.")

        lines.append("=" * 50)
        return "\n".join(lines)

    def build_tool_context(self, tool_name: str, result: dict) -> str:
        if not result:
            return ""

        lines = [
            f"=== {tool_name.upper()} TOOL RESULT CONTEXT ===",
            f"Tool: {tool_name}",
            f"Target: {result.get('target', 'Unknown')}",
            "",
        ]

        if tool_name == "ssl":
            lines.extend(self._build_ssl_context(result))
        elif tool_name == "http_headers":
            lines.extend(self._build_http_headers_context(result))
        elif tool_name == "dns":
            lines.extend(self._build_dns_context(result))
        elif tool_name == "subdomain":
            lines.extend(self._build_subdomain_context(result))
        elif tool_name == "whois":
            lines.extend(self._build_whois_context(result))
        elif tool_name == "geoip":
            lines.extend(self._build_geoip_context(result))
        else:
            lines.extend(self._build_generic_tool_context(result))

        lines.append("=" * 50)
        return "\n".join(lines)

    def _build_ssl_context(self, result: dict) -> list[str]:
        lines = []
        status = result.get("status", "unknown")

        if status == "failed":
            lines.append(f"ERROR: {result.get('error', 'Unknown error')}")
            return lines

        lines.append("SSL/TLS Configuration:")

        protocol = result.get("protocol_version")
        if protocol:
            lines.append(f"  Protocol: {protocol}")
            if protocol in ("TLSv1", "TLSv1.1"):
                lines.append("  WARNING: Deprecated TLS version detected")

        cipher = result.get("cipher")
        if cipher:
            lines.append(f"  Cipher: {cipher}")

        subject = result.get("subject", "")
        issuer = result.get("issuer", "")
        lines.append(f"  Subject: {subject}")
        lines.append(f"  Issuer: {issuer}")

        not_before = result.get("not_before")
        not_after = result.get("not_after")
        if not_before:
            lines.append(f"  Valid From: {not_before}")
        if not_after:
            lines.append(f"  Valid Until: {not_after}")

        if subject == issuer:
            lines.append("  WARNING: Self-signed certificate detected")

        return lines

    def _build_http_headers_context(self, result: dict) -> list[str]:
        lines = []
        status = result.get("status", "unknown")

        if status in ("failed", "timeout"):
            lines.append(f"ERROR: {result.get('error', 'Connection failed')}")
            return lines

        lines.append(f"URL: {result.get('url', 'N/A')}")
        lines.append(f"Status Code: {result.get('status_code', 'N/A')}")
        lines.append("")

        headers = result.get("headers", {})
        if not headers:
            lines.append("No headers received")
            return lines

        security_headers = {
            "strict-transport-security": "HSTS",
            "content-security-policy": "CSP",
            "x-content-type-options": "X-Content-Type-Options",
            "x-frame-options": "X-Frame-Options",
            "x-xss-protection": "X-XSS-Protection",
            "referrer-policy": "Referrer-Policy",
            "permissions-policy": "Permissions-Policy",
        }

        lines.append("Security Headers:")

        missing_security = []
        for header, name in security_headers.items():
            if header.lower() in [h.lower() for h in headers.keys()]:
                lines.append(f"  [OK] {name}: Present")
            else:
                missing_security.append(name)
                lines.append(f"  [MISSING] {name}")

        if missing_security:
            lines.append("")
            lines.append("Missing security headers should be added to improve security posture.")

        return lines

    def _build_dns_context(self, result: dict) -> list[str]:
        lines = []
        status = result.get("status", "unknown")

        if status == "failed":
            lines.append(f"ERROR: {result.get('error', 'DNS lookup failed')}")
            return lines

        record_type = result.get("record_type", "A")
        lines.append(f"Record Type: {record_type}")

        records = result.get("records", [])
        if records:
            lines.append(f"Records ({len(records)}):")
            for record in records[:10]:
                lines.append(f"  - {record}")
            if len(records) > 10:
                lines.append(f"  ... and {len(records) - 10} more")
        else:
            lines.append("No records found")

        return lines

    def _build_subdomain_context(self, result: dict) -> list[str]:
        lines = []

        domain = result.get("domain", "Unknown")
        total_found = result.get("total_found", 0)
        subdomains = result.get("subdomains_found", [])

        lines.append(f"Domain: {domain}")
        lines.append(f"Total Subdomains Found: {total_found}")

        if subdomains:
            lines.append("")
            lines.append("Discovered Subdomains:")
            for sub in subdomains[:20]:
                lines.append(f"  - {sub}")
            if len(subdomains) > 20:
                lines.append(f"  ... and {len(subdomains) - 20} more")
        else:
            lines.append("No subdomains discovered")

        return lines

    def _build_whois_context(self, result: dict) -> list[str]:
        lines = []
        status = result.get("status", "unknown")

        if status == "failed":
            lines.append(f"ERROR: {result.get('error', 'WHOIS lookup failed')}")
            return lines

        domain_name = result.get("domain_name")
        if domain_name:
            lines.append(f"Domain Name: {domain_name}")

        registrar = result.get("registrar")
        if registrar:
            lines.append(f"Registrar: {registrar}")

        creation = result.get("creation_date")
        expiration = result.get("expiration_date")
        if creation:
            lines.append(f"Created: {creation}")
        if expiration:
            lines.append(f"Expires: {expiration}")

        name_servers = result.get("name_servers")
        if name_servers:
            ns_list = name_servers if isinstance(name_servers, list) else [name_servers]
            lines.append(f"Name Servers: {', '.join(ns_list[:3])}")

        return lines

    def _build_geoip_context(self, result: dict) -> list[str]:
        lines = []
        status = result.get("status", "unknown")

        if status == "failed":
            lines.append(f"ERROR: {result.get('error', 'GeoIP lookup failed')}")
            return lines

        ip = result.get("ip", result.get("target", "Unknown"))
        lines.append(f"IP Address: {ip}")

        location_parts = [
            result.get("city"),
            result.get("region"),
            result.get("country"),
        ]
        location = ", ".join(filter(None, location_parts))
        if location:
            lines.append(f"Location: {location}")

        isp = result.get("isp")
        if isp:
            lines.append(f"ISP: {isp}")

        org = result.get("org")
        if org:
            lines.append(f"Organization: {org}")

        return lines

    def _build_generic_tool_context(self, result: dict) -> list[str]:
        lines = []
        lines.append("Tool Result Data:")
        lines.append(f"  Status: {result.get('status', 'unknown')}")

        for key, value in result.items():
            if key not in ("target", "status") and value:
                lines.append(f"  {key}: {value}")

        return lines
