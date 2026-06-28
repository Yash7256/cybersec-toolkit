"""
Web application security scanner.

All severities are lowercase strings to match the frontend SEVERITY_STYLES keys:
  critical | high | medium | low | info
"""
import asyncio
import re
import socket
import time
from dataclasses import dataclass, field
from typing import List, Set, Dict, Optional, Tuple
from urllib.parse import urljoin, urlparse

import httpx

CRITICAL = "critical"
HIGH     = "high"
MEDIUM   = "medium"
LOW      = "low"
INFO     = "info"

_SEV_RANK = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class WebAppVulnerability:
    vuln_type: str
    severity: str        # lowercase
    url: str
    parameter: Optional[str]
    evidence: Optional[str]
    recommendation: str
    category: str = ""   # e.g. "tls", "headers", "injection", "access-control"


@dataclass
class CrawlResult:
    url: str
    status_code: int
    content_type: Optional[str]
    forms: List[dict]
    links: List[str]
    response_headers: Dict[str, str] = field(default_factory=dict)
    body_snippet: str = ""  # first 4 KB, used for fingerprinting


@dataclass
class TechFingerprint:
    cms: Optional[str] = None
    framework: Optional[str] = None
    server: Optional[str] = None
    languages: List[str] = field(default_factory=list)
    libraries: List[str] = field(default_factory=list)
    login_paths: List[str] = field(default_factory=list)


@dataclass
class WebAppScanResult:
    target: str
    base_url: str
    pages_crawled: int
    vulnerabilities: List[WebAppVulnerability]
    total_vulns: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    scan_duration: float
    fingerprint: Optional[dict]
    error: Optional[str]


# ---------------------------------------------------------------------------
# WebAppScanner class — constants
# ---------------------------------------------------------------------------

class WebAppScanner:

    # --- Exposed sensitive paths ---
    SENSITIVE_FILES = [
        ".env", ".env.local", ".env.production",
        ".git/config", ".git/HEAD",
        "robots.txt", "sitemap.xml",
        "wp-config.php", "wp-login.php", "wp-admin/",
        "config.php", "configuration.php", "settings.php",
        ".htaccess", "web.config",
        "phpinfo.php", "info.php", "test.php",
        "admin/", "administrator/", "phpmyadmin/", "pma/",
        "backup.zip", "backup.tar.gz", "dump.sql", "database.sql", "db.sql",
        ".DS_Store", "package.json", "yarn.lock", "composer.json",
        "Dockerfile", "docker-compose.yml",
        "server-status", "server-info",
        "actuator/", "actuator/env", "actuator/health",
        "api/swagger.json", "api/openapi.json", "swagger-ui.html",
        "graphql", "graphiql",
    ]

    # --- Admin panel paths ---
    ADMIN_PATHS = [
        "/admin", "/admin/", "/administrator/", "/wp-admin/",
        "/phpmyadmin/", "/pma/", "/cpanel/", "/webmail/",
        "/manager/html", "/jmx-console/", "/admin-console/",
        "/login", "/login.php", "/signin", "/auth/login",
        "/user/login", "/account/login", "/panel/",
        "/dashboard", "/console/", "/control/",
    ]

    SQLI_PAYLOADS = ["'", "''", "' OR '1'='1", "' OR 1=1--", "' UNION SELECT NULL--"]
    XSS_PAYLOADS  = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
                     "'><svg onload=alert(1)>"]
    SSTI_PAYLOADS = ["{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>", "{{config}}"]
    TRAVERSAL_PAYLOADS = ["../etc/passwd", "../../etc/passwd", "../../../etc/passwd",
                          "....//....//etc/passwd", "%2e%2e%2fetc%2fpasswd"]

    SQL_ERRORS = [
        "sql syntax", "mysql_fetch", "ORA-", "syntax error",
        "unclosed quotation", "quoted string not properly terminated",
        "pg_query()", "sqlite_", "Microsoft OLE DB", "Warning: mysql",
        "You have an error in your SQL syntax", "SQLSTATE",
        "PDOException", "psycopg2",
    ]

    SECURITY_HEADERS: Dict[str, Tuple[str, str]] = {
        "Strict-Transport-Security": (HIGH,   "Prevents protocol downgrade / MITM attacks"),
        "Content-Security-Policy":   (HIGH,   "Mitigates XSS and data injection"),
        "X-Frame-Options":           (MEDIUM, "Prevents clickjacking via iframe"),
        "X-Content-Type-Options":    (MEDIUM, "Prevents MIME-type sniffing"),
        "Referrer-Policy":           (LOW,    "Controls referrer leakage"),
        "Permissions-Policy":        (LOW,    "Restricts browser feature access"),
    }

    # CMS / framework / library fingerprints: (pattern, name, category)
    _FINGERPRINTS = [
        # CMS
        (r"wp-content|wp-includes|wordpress", "WordPress", "cms"),
        (r"Joomla!|/components/com_", "Joomla", "cms"),
        (r"Drupal|sites/default/files", "Drupal", "cms"),
        (r"Magento|mage/|Mage\.", "Magento", "cms"),
        (r"TYPO3", "TYPO3", "cms"),
        # Frameworks
        (r"Django|csrfmiddlewaretoken|__admin__", "Django", "framework"),
        (r"Rails|X-Powered-By: Phusion Passenger|_rails_", "Ruby on Rails", "framework"),
        (r"Laravel|laravel_session", "Laravel", "framework"),
        (r"ASP\.NET|__VIEWSTATE|__EVENTVALIDATION", "ASP.NET", "framework"),
        (r"Spring Boot|Whitelabel Error Page", "Spring Boot", "framework"),
        # JS libraries (from body)
        (r"jquery[./\-](\d+\.\d+\.\d+)", "jQuery", "library"),
        (r"react\.development|react\.production|__REACT", "React", "library"),
        (r"angular(?:\.min)?\.js|ng-version", "Angular", "library"),
        (r"vue\.(?:min\.)?js|__vue__", "Vue.js", "library"),
        (r"bootstrap(?:\.min)?\.(?:js|css)", "Bootstrap", "library"),
    ]

    def __init__(self, max_pages: int = 20, timeout: float = 10.0):
        self.max_pages = max_pages
        self.timeout = timeout
        self.visited_urls: Set[str] = set()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _v(vuln_type: str, severity: str, url: str, param: Optional[str],
           evidence: Optional[str], recommendation: str, category: str = "") -> WebAppVulnerability:
        return WebAppVulnerability(
            vuln_type=vuln_type, severity=severity, url=url,
            parameter=param, evidence=evidence,
            recommendation=recommendation, category=category,
        )

    @staticmethod
    def _base_domain(url: str) -> str:
        p = urlparse(url)
        return p.netloc.split(":")[0]

    @staticmethod
    def _abs(base: str, href: str) -> str:
        return urljoin(base, href)

    # ------------------------------------------------------------------
    # SSRF-safe redirect helper
    # ------------------------------------------------------------------

    _MAX_REDIRECT_HOPS = 5

    @staticmethod
    def _resolve_ip(url: str) -> str | None:
        host = urlparse(url).hostname
        if not host:
            return None
        try:
            return socket.getaddrinfo(host, None)[0][4][0]
        except OSError:
            return None

    async def _safe_get(
        self,
        url: str,
        client: httpx.AsyncClient,
        allow_private: bool = False,
        **kwargs,
    ) -> httpx.Response | None:
        """GET with manual redirect following + SSRF re-validation on each hop."""
        from cybersec.core.tools.port_scanner import _is_scan_target_allowed  # lazy import
        current = url
        for _ in range(self._MAX_REDIRECT_HOPS + 1):
            if not allow_private:
                ip = self._resolve_ip(current)
                if ip is None or not _is_scan_target_allowed(ip):
                    return None
            resp = await client.get(current, follow_redirects=False, **kwargs)
            if resp.status_code not in (301, 302, 303, 307, 308):
                return resp
            location = resp.headers.get("location")
            if not location:
                return resp
            current = location if location.startswith(("http://", "https://")) else urljoin(current, location)
        return None  # exceeded max hops

    # ------------------------------------------------------------------
    # Crawl
    # ------------------------------------------------------------------

    async def crawl(self, base_url: str, client: httpx.AsyncClient, allow_private: bool = False) -> List[CrawlResult]:
        queue = [base_url]
        results: List[CrawlResult] = []
        domain = self._base_domain(base_url)

        while queue and len(self.visited_urls) < self.max_pages:
            url = queue.pop(0)
            if url in self.visited_urls:
                continue
            self.visited_urls.add(url)

            try:
                response = await self._safe_get(url, client, allow_private=allow_private)
                if response is None:
                    continue
                text = response.text

                href_pattern = r'href=["\'](https?://[^"\'<>\s]+|/[^"\'<>\s]*)["\']'
                links: List[str] = []
                for raw in re.findall(href_pattern, text):
                    link = self._abs(base_url, raw)
                    if domain in self._base_domain(link):
                        links.append(link)
                        if link not in self.visited_urls and link not in queue:
                            queue.append(link)

                # Form extraction
                forms: List[dict] = []
                for block in re.split(r"<form", text, flags=re.IGNORECASE)[1:]:
                    tag_end = block.find(">")
                    if tag_end == -1:
                        continue
                    ot = block[:tag_end]
                    m_a = re.search(r'action=["\']([^"\']*)["\']', ot, re.IGNORECASE)
                    m_m = re.search(r'method=["\']([^"\']*)["\']', ot, re.IGNORECASE)
                    action = self._abs(base_url, m_a.group(1)) if m_a else url
                    method = m_m.group(1).upper() if m_m else "GET"
                    fb = block.split("</form>", 1)[0]
                    inputs = list(dict.fromkeys(
                        re.findall(r'<input[^>]*name=["\']([^"\']+)["\']', fb, re.IGNORECASE) +
                        re.findall(r'<select[^>]*name=["\']([^"\']+)["\']', fb, re.IGNORECASE) +
                        re.findall(r'<textarea[^>]*name=["\']([^"\']+)["\']', fb, re.IGNORECASE)
                    ))
                    if inputs:
                        forms.append({"action": action, "method": method, "inputs": inputs})

                results.append(CrawlResult(
                    url=url, status_code=response.status_code,
                    content_type=response.headers.get("content-type"),
                    forms=forms, links=links,
                    response_headers=dict(response.headers),
                    body_snippet=text[:4096],
                ))
            except Exception:
                continue

        return results

    # ------------------------------------------------------------------
    # TLS / SSL check (reuses existing ssl_audit)
    # ------------------------------------------------------------------

    async def check_tls(self, base_url: str) -> List[WebAppVulnerability]:
        vulns: List[WebAppVulnerability] = []
        parsed = urlparse(base_url)
        if parsed.scheme != "https":
            return vulns
        host = parsed.netloc.split(":")[0]
        port = int(parsed.port or 443)

        try:
            from cybersec.core.tools.ssl import ssl_audit
            r = await ssl_audit(host, port)
        except Exception as exc:
            vulns.append(self._v("TLS_AUDIT_FAILED", INFO, base_url, None,
                str(exc)[:200], "Verify TLS is properly configured.", "tls"))
            return vulns

        if r.error:
            vulns.append(self._v("TLS_ERROR", MEDIUM, base_url, None,
                r.error, "Review and fix TLS configuration.", "tls"))
            return vulns

        if r.cert and r.cert.is_expired:
            vulns.append(self._v("TLS_CERT_EXPIRED", CRITICAL, base_url, None,
                f"Certificate expired. Days remaining: {r.cert.days_remaining}",
                "Renew the TLS certificate immediately.", "tls"))
        elif r.cert and 0 < r.cert.days_remaining < 30:
            vulns.append(self._v("TLS_CERT_EXPIRING_SOON", MEDIUM, base_url, None,
                f"Certificate expires in {r.cert.days_remaining} day(s).",
                "Renew the TLS certificate before it expires.", "tls"))

        if r.is_self_signed:
            vulns.append(self._v("TLS_SELF_SIGNED", HIGH, base_url, None,
                "Certificate is self-signed and not trusted by browsers.",
                "Replace with a certificate issued by a trusted CA (e.g. Let's Encrypt).", "tls"))

        if not r.supports_tls12:
            vulns.append(self._v("TLS_NO_TLS12", HIGH, base_url, None,
                "Server does not support TLS 1.2.",
                "Enable TLS 1.2 and TLS 1.3; disable TLS 1.0/1.1 and SSL.", "tls"))

        if r.tls_version and r.tls_version in {"TLSv1", "TLSv1.1", "SSLv3", "SSLv2"}:
            vulns.append(self._v("TLS_WEAK_VERSION", HIGH, base_url, None,
                f"Server negotiated deprecated protocol: {r.tls_version}",
                "Disable TLS 1.0, TLS 1.1, SSLv3, and SSLv2; require TLS 1.2+.", "tls"))

        if r.cipher_suite:
            weak_markers = {"RC4", "DES", "3DES", "NULL", "EXPORT", "MD5", "anon"}
            if any(m.upper() in r.cipher_suite.upper() for m in weak_markers):
                vulns.append(self._v("TLS_WEAK_CIPHER", HIGH, base_url, None,
                    f"Weak cipher suite negotiated: {r.cipher_suite}",
                    "Disable weak ciphers (RC4, DES, 3DES, EXPORT, NULL, MD5); prefer ECDHE+AES-GCM.", "tls"))

        if r.cert:
            cn = r.cert.subject.get("commonName", "")
            domain = host
            if cn and domain and not (cn == domain or domain.endswith("." + cn.lstrip("*."))):
                if not any(
                    san == domain or domain.endswith("." + san.lstrip("*."))
                    for san in (r.cert.san or [])
                ):
                    vulns.append(self._v("TLS_CERT_HOSTNAME_MISMATCH", HIGH, base_url, None,
                        f"Certificate CN/SAN '{cn}' does not match host '{domain}'.",
                        "Ensure the certificate covers all hostnames the site responds to.", "tls"))

        return vulns

    # ------------------------------------------------------------------
    # HTTP headers + cookies + protocol
    # ------------------------------------------------------------------

    async def check_headers(self, url: str, client: httpx.AsyncClient, allow_private: bool = False) -> List[WebAppVulnerability]:
        vulns: List[WebAppVulnerability] = []
        try:
            resp = await self._safe_get(url, client, allow_private=allow_private)
            if resp is None:
                return vulns
            hl = {k.lower(): v for k, v in resp.headers.items()}

            for header, (sev, desc) in self.SECURITY_HEADERS.items():
                if header.lower() not in hl:
                    vulns.append(self._v("MISSING_HEADER", sev, url, header,
                        f"'{header}' not set. {desc}.",
                        f"Add '{header}' to all HTTP responses.", "headers"))

            # Check CSP quality if present
            csp = hl.get("content-security-policy", "")
            if csp:
                if "unsafe-inline" in csp and "unsafe-eval" in csp:
                    vulns.append(self._v("WEAK_CSP", MEDIUM, url, "Content-Security-Policy",
                        "CSP contains both 'unsafe-inline' and 'unsafe-eval' — effectively neutralises XSS protection.",
                        "Remove 'unsafe-inline' and 'unsafe-eval'; use nonces or hashes instead.", "headers"))
                elif "unsafe-inline" in csp:
                    vulns.append(self._v("WEAK_CSP", LOW, url, "Content-Security-Policy",
                        "CSP contains 'unsafe-inline', weakening XSS protection.",
                        "Replace 'unsafe-inline' with nonce-based or hash-based CSP directives.", "headers"))

            # HSTS quality
            hsts = hl.get("strict-transport-security", "")
            if hsts:
                m = re.search(r"max-age=(\d+)", hsts)
                max_age = int(m.group(1)) if m else 0
                if max_age < 31536000:
                    vulns.append(self._v("WEAK_HSTS", LOW, url, "Strict-Transport-Security",
                        f"HSTS max-age is {max_age}s (< 1 year).",
                        "Set HSTS max-age to at least 31536000 (1 year); add includeSubDomains and preload.", "headers"))

            # Leaky server headers
            for leaky in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator"):
                val = hl.get(leaky)
                if val:
                    vulns.append(self._v("INFO_DISCLOSURE", LOW, url, leaky,
                        f"{leaky}: {val}",
                        f"Remove or genericise the '{leaky}' header to reduce fingerprinting.", "headers"))

            # Insecure cookies — check all Set-Cookie headers
            for raw_cookie in resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else [resp.headers.get("set-cookie", "")]:
                if not raw_cookie:
                    continue
                lc = raw_cookie.lower()
                issues = []
                if "httponly" not in lc:
                    issues.append("missing HttpOnly")
                if "secure" not in lc:
                    issues.append("missing Secure")
                if "samesite" not in lc:
                    issues.append("missing SameSite")
                if issues:
                    cname = raw_cookie.split("=", 1)[0].strip()
                    vulns.append(self._v("INSECURE_COOKIE", MEDIUM, url, cname,
                        f"Cookie flags missing: {', '.join(issues)}.",
                        "Set HttpOnly, Secure, and SameSite=Strict/Lax on session cookies.", "headers"))

            # Plaintext HTTP
            if url.startswith("http://"):
                vulns.append(self._v("PLAINTEXT_HTTP", HIGH, url, None,
                    "Site served over unencrypted HTTP.",
                    "Redirect all HTTP traffic to HTTPS and deploy a valid TLS certificate.", "headers"))

            # Cache-Control on authenticated-looking pages
            cache = hl.get("cache-control", "")
            if not cache or ("no-store" not in cache and "private" not in cache):
                if resp.status_code == 200 and any(
                    kw in url.lower() for kw in ("/admin", "/account", "/profile", "/dashboard", "/login")
                ):
                    vulns.append(self._v("CACHEABLE_SENSITIVE_PAGE", LOW, url, "Cache-Control",
                        f"Cache-Control: {cache or '(not set)'} — sensitive page may be cached.",
                        "Add 'Cache-Control: no-store, private' to authenticated/sensitive responses.", "headers"))

        except Exception as exc:
            vulns.append(self._v("REQUEST_FAILED", INFO, url, None,
                str(exc)[:200], "Verify the site is reachable.", "headers"))
        return vulns

    # ------------------------------------------------------------------
    # HTTP methods (TRACE, PUT, DELETE, etc.)
    # ------------------------------------------------------------------

    async def check_http_methods(self, url: str, client: httpx.AsyncClient, allow_private: bool = False) -> List[WebAppVulnerability]:
        vulns: List[WebAppVulnerability] = []
        try:
            resp = await client.options(url, follow_redirects=False)
            allow = resp.headers.get("Allow", resp.headers.get("allow", ""))
            methods = [m.strip().upper() for m in allow.split(",") if m.strip()]
        except Exception:
            return vulns

        if "TRACE" in methods:
            vulns.append(self._v("HTTP_TRACE_ENABLED", MEDIUM, url, "Allow",
                f"TRACE method enabled (Allow: {allow}).",
                "Disable TRACE method on the web server to prevent Cross-Site Tracing (XST).", "access-control"))

        for dangerous in ("PUT", "DELETE", "PATCH"):
            if dangerous in methods:
                vulns.append(self._v("DANGEROUS_HTTP_METHOD", MEDIUM, url, "Allow",
                    f"Method {dangerous} is permitted (Allow: {allow}).",
                    f"Disable {dangerous} unless required by a REST API; restrict to authenticated users.", "access-control"))

        # Also probe TRACE directly
        try:
            tr = await client.request("TRACE", url, follow_redirects=False)
            if tr.status_code == 200 and "TRACE" in tr.text.upper():
                if not any(v.vuln_type == "HTTP_TRACE_ENABLED" for v in vulns):
                    vulns.append(self._v("HTTP_TRACE_ENABLED", MEDIUM, url, None,
                        f"TRACE request returned HTTP 200 with request echo.",
                        "Disable TRACE method on the web server.", "access-control"))
        except Exception:
            pass

        return vulns

    # ------------------------------------------------------------------
    # CORS
    # ------------------------------------------------------------------

    async def check_cors(self, url: str, client: httpx.AsyncClient, allow_private: bool = False) -> List[WebAppVulnerability]:
        vulns: List[WebAppVulnerability] = []
        evil = "https://evil.com"
        for method in ("GET", "OPTIONS"):
            try:
                if method == "OPTIONS":
                    resp = await client.options(url, headers={"Origin": evil}, follow_redirects=False)
                else:
                    resp = await self._safe_get(url, client, allow_private=allow_private, headers={"Origin": evil})
                    if resp is None:
                        continue
            except Exception:
                continue

            ao = resp.headers.get("Access-Control-Allow-Origin", "")
            ac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
            if not ao:
                continue

            if ao == "*" and ac == "true":
                vulns.append(self._v("CORS_WILDCARD_WITH_CREDENTIALS", CRITICAL, url,
                    "Access-Control-Allow-Origin",
                    f"Wildcard ACAO with Allow-Credentials: true (method={method}).",
                    "Never combine ACAO: * with Allow-Credentials: true.", "cors"))
                break
            elif ao == "*":
                vulns.append(self._v("CORS_WILDCARD", MEDIUM, url,
                    "Access-Control-Allow-Origin",
                    f"ACAO: * (method={method}).",
                    "Restrict ACAO to an explicit allowlist of trusted origins.", "cors"))
                break
            elif ao == evil:
                sev = CRITICAL if ac == "true" else HIGH
                vulns.append(self._v("CORS_REFLECTED_ORIGIN", sev, url,
                    "Access-Control-Allow-Origin",
                    f"Server reflects arbitrary origin '{evil}'. Credentials: {ac} (method={method}).",
                    "Do not dynamically echo the Origin header; use an explicit allowlist.", "cors"))
                break
        return vulns

    # ------------------------------------------------------------------
    # Exposed sensitive files
    # ------------------------------------------------------------------

    async def check_exposed_files(self, base_url: str, client: httpx.AsyncClient) -> List[WebAppVulnerability]:
        async def _probe(path: str) -> Optional[WebAppVulnerability]:
            u = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
            try:
                r = await client.get(u, follow_redirects=False)
                if r.status_code == 200:
                    sev = HIGH if path in {".env", ".git/config", ".git/HEAD",
                                           "wp-config.php", "config.php", "configuration.php"} else MEDIUM
                    preview = r.text[:100].replace("\n", " ").strip()
                    return self._v("EXPOSED_FILE", sev, u, path,
                        f"HTTP 200 — preview: {preview!r}" if preview else "HTTP 200",
                        f"Deny public access to '{path}' via server config or firewall.", "access-control")
                if r.status_code in (301, 302):
                    return self._v("EXPOSED_FILE", LOW, u, path,
                        f"HTTP {r.status_code} redirect — resource may be accessible.",
                        f"Verify '{path}' is not reachable after redirect.", "access-control")
            except Exception:
                pass
            return None

        results = await asyncio.gather(*(_probe(p) for p in self.SENSITIVE_FILES))
        return [r for r in results if r]

    # ------------------------------------------------------------------
    # Admin panel enumeration
    # ------------------------------------------------------------------

    async def check_admin_panels(self, base_url: str, client: httpx.AsyncClient, allow_private: bool = False) -> List[WebAppVulnerability]:
        vulns: List[WebAppVulnerability] = []

        async def _probe(path: str) -> Optional[WebAppVulnerability]:
            u = f"{base_url.rstrip('/')}{path}"
            try:
                r = await self._safe_get(u, client, allow_private=allow_private)
                if r is None:
                    return None
                if r.status_code == 200:
                    body_lower = r.text.lower()
                    is_login = any(kw in body_lower for kw in (
                        "password", "username", "login", "sign in", "email", "user"
                    ))
                    sev = HIGH if is_login else MEDIUM
                    hint = "Login form detected." if is_login else "Page returned 200."
                    return self._v("ADMIN_PANEL_EXPOSED", sev, u, path,
                        f"Admin/login panel accessible without authentication. {hint}",
                        "Restrict access via IP allowlist, VPN, or multi-factor authentication.", "access-control")
                if r.status_code == 403:
                    return self._v("ADMIN_PANEL_FORBIDDEN", LOW, u, path,
                        "Admin path exists but returns 403 — may be bypassed.",
                        "Verify access controls cannot be bypassed (path traversal, case-sensitivity, etc.).", "access-control")
            except Exception:
                pass
            return None

        results = await asyncio.gather(*(_probe(p) for p in self.ADMIN_PATHS))
        return [r for r in results if r]

    # ------------------------------------------------------------------
    # Directory listing
    # ------------------------------------------------------------------

    async def check_directory_listing(self, pages: List[CrawlResult]) -> List[WebAppVulnerability]:
        vulns: List[WebAppVulnerability] = []
        dir_pattern = re.compile(
            r"<title>\s*index of|<h1>\s*index of|directory listing for /|"
            r"parent directory.*last modified",
            re.IGNORECASE
        )
        for page in pages:
            if dir_pattern.search(page.body_snippet):
                vulns.append(self._v("DIRECTORY_LISTING", HIGH, page.url, None,
                    "Server returns an auto-generated directory index.",
                    "Disable directory listing in server config (Options -Indexes for Apache; autoindex off for nginx).",
                    "access-control"))
        return vulns

    # ------------------------------------------------------------------
    # Open redirect
    # ------------------------------------------------------------------

    async def check_open_redirect(self, base_url: str, client: httpx.AsyncClient) -> List[WebAppVulnerability]:
        evil = "https://evil.com"
        params = ["redirect", "url", "next", "return", "returnUrl", "redir", "destination", "goto", "continue"]
        for param in params:
            u = f"{base_url.rstrip('/')}/?{param}={evil}"
            try:
                r = await client.get(u, follow_redirects=False)
                loc = r.headers.get("location", "")
                if r.status_code in (301, 302, 303, 307, 308) and evil in loc:
                    return [self._v("OPEN_REDIRECT", MEDIUM, u, param,
                        f"HTTP {r.status_code} Location: {loc}",
                        f"Validate redirect targets against an explicit whitelist; reject '{param}' pointing off-domain.",
                        "injection")]
            except Exception:
                pass
        return []

    # ------------------------------------------------------------------
    # Technology fingerprinting
    # ------------------------------------------------------------------

    def fingerprint(self, pages: List[CrawlResult], base_url: str) -> TechFingerprint:
        fp = TechFingerprint()
        combined = " ".join(p.body_snippet for p in pages[:5])
        headers_combined = " ".join(
            f"{k}: {v}"
            for p in pages[:3]
            for k, v in p.response_headers.items()
        )
        blob = (combined + " " + headers_combined).lower()

        server_header = ""
        for p in pages[:1]:
            server_header = p.response_headers.get("server", p.response_headers.get("Server", ""))

        fp.server = server_header or None

        for pattern, name, category in self._FINGERPRINTS:
            if re.search(pattern, blob, re.IGNORECASE):
                if category == "cms" and not fp.cms:
                    fp.cms = name
                elif category == "framework" and not fp.framework:
                    fp.framework = name
                elif category == "library" and name not in fp.libraries:
                    fp.libraries.append(name)

        # Language hints from headers / paths
        for lang, patterns in [
            ("PHP",    [r"\.php", r"x-powered-by: php", r"phpsessid"]),
            ("Python", [r"python|django|flask|wsgi", r"\.py"]),
            ("Java",   [r"jsessionid|\.jsp|\.do\b|java|tomcat"]),
            ("Ruby",   [r"rack|passenger|_rails|\.rb\b"]),
            ("Node.js",[r"express|node\.js|connect\."]),
            (".NET",   [r"asp\.net|__viewstate|x-aspnet"]),
        ]:
            if any(re.search(p, blob, re.IGNORECASE) for p in patterns):
                if lang not in fp.languages:
                    fp.languages.append(lang)

        # Login page detection
        for p in pages:
            if any(kw in p.url.lower() for kw in ("/login", "/signin", "/auth", "/wp-login")):
                if p.url not in fp.login_paths:
                    fp.login_paths.append(p.url)

        return fp

    # ------------------------------------------------------------------
    # Injection checks (SQL, XSS, SSTI, CMDi, path traversal)
    # ------------------------------------------------------------------

    async def check_sqli(self, url: str, forms: List[dict], client: httpx.AsyncClient, allow_private: bool = False) -> List[WebAppVulnerability]:
        vulns: List[WebAppVulnerability] = []
        for form in forms:
            for name in form["inputs"]:
                for payload in self.SQLI_PAYLOADS[:3]:
                    try:
                        data = {k: "test" for k in form["inputs"]}
                        data[name] = payload
                        if form["method"] == "POST":
                            r = await client.post(form["action"], data=data, follow_redirects=False)
                        else:
                            r = await self._safe_get(form["action"], client, allow_private=allow_private, params=data)
                            if r is None:
                                continue
                        for err in self.SQL_ERRORS:
                            if err.lower() in r.text.lower():
                                idx = r.text.lower().find(err.lower())
                                snippet = r.text[max(0, idx - 20):idx + 80]
                                vulns.append(self._v("SQL_INJECTION", CRITICAL, url, name,
                                    snippet[:120],
                                    "Use parameterized queries / prepared statements; never interpolate user input into SQL.",
                                    "injection"))
                                break
                        else:
                            continue
                        break
                    except Exception:
                        pass
        return vulns

    async def check_xss(self, url: str, forms: List[dict], client: httpx.AsyncClient, allow_private: bool = False) -> List[WebAppVulnerability]:
        vulns: List[WebAppVulnerability] = []
        # Also probe GET parameters from URL
        url_params: List[str] = []
        if "?" in url:
            qs = url.split("?", 1)[1]
            url_params = [kv.split("=")[0] for kv in qs.split("&") if "=" in kv]

        async def _probe_form(form, name, payload):
            data = {k: "test" for k in form["inputs"]}
            data[name] = payload
            if form["method"] == "POST":
                r = await client.post(form["action"], data=data, follow_redirects=False)
            else:
                r = await self._safe_get(form["action"], client, allow_private=allow_private, params=data)
                if r is None:
                    return None
            if payload in r.text:
                return self._v("XSS", HIGH, url, name,
                    f"Payload reflected: {payload[:60]}",
                    "HTML-encode all user output; implement a strict Content-Security-Policy.", "injection")
            return None

        async def _probe_param(param, payload):
            u = re.sub(rf"([?&]{re.escape(param)}=)[^&]*", rf"\g<1>{payload}", url)
            r = await self._safe_get(u, client, allow_private=allow_private)
            if r is None:
                return None
            if payload in r.text:
                return self._v("XSS", HIGH, url, param,
                    f"URL param reflected: {payload[:60]}",
                    "HTML-encode all user output; implement a strict Content-Security-Policy.", "injection")
            return None

        tasks = []
        for form in forms:
            for name in form["inputs"]:
                for payload in self.XSS_PAYLOADS[:2]:
                    tasks.append(_probe_form(form, name, payload))
        for param in url_params:
            for payload in self.XSS_PAYLOADS[:2]:
                tasks.append(_probe_param(param, payload))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, WebAppVulnerability):
                vulns.append(r)
        return vulns

    async def check_csrf(self, url: str, forms: List[dict]) -> List[WebAppVulnerability]:
        vulns: List[WebAppVulnerability] = []
        for form in forms:
            if form["method"] == "POST":
                has_token = any(
                    t in inp.lower()
                    for inp in form["inputs"]
                    for t in ("csrf", "token", "_token", "authenticity_token", "nonce", "xsrf")
                )
                if not has_token:
                    vulns.append(self._v("CSRF", MEDIUM, url, None,
                        f"POST form at '{form['action']}' has no CSRF token.",
                        "Add an unpredictable, per-session CSRF token to all state-changing forms.", "injection"))
        return vulns

    async def check_ssti(self, url: str, forms: List[dict], client: httpx.AsyncClient, allow_private: bool = False) -> List[WebAppVulnerability]:
        vulns: List[WebAppVulnerability] = []
        for form in forms:
            for name in form["inputs"]:
                for payload in self.SSTI_PAYLOADS:
                    try:
                        data = {k: "test" for k in form["inputs"]}
                        data[name] = payload
                        if form["method"] == "POST":
                            r = await client.post(form["action"], data=data, follow_redirects=False)
                        else:
                            r = await self._safe_get(form["action"], client, allow_private=allow_private, params=data)
                            if r is None:
                                continue
                        if "49" in r.text and payload in ("{{7*7}}", "${7*7}", "#{7*7}"):
                            vulns.append(self._v("SSTI", CRITICAL, url, name,
                                f"Template expression '{payload}' evaluated to 49.",
                                "Never pass user input to template engines unsanitised; use sandboxed evaluation.", "injection"))
                            break
                    except Exception:
                        pass
        return vulns

    async def check_path_traversal(self, base_url: str, client: httpx.AsyncClient, allow_private: bool = False) -> List[WebAppVulnerability]:
        vulns: List[WebAppVulnerability] = []
        for payload in self.TRAVERSAL_PAYLOADS:
            for param in ("file", "path", "page", "include", "template", "load", "doc"):
                u = f"{base_url.rstrip('/')}/?{param}={payload}"
                try:
                    r = await self._safe_get(u, client, allow_private=allow_private)
                    if r is None:
                        continue
                    if r.status_code == 200 and (
                        "root:" in r.text or "[fonts]" in r.text or "daemon:" in r.text
                    ):
                        vulns.append(self._v("PATH_TRAVERSAL", CRITICAL, u, param,
                            f"Traversal payload '{payload}' returned file contents.",
                            "Validate and canonicalise file paths; use an allowlist of permitted files.", "injection"))
                        return vulns
                except Exception:
                    pass
        return vulns

    # ------------------------------------------------------------------
    # DNS / email security (SPF, DMARC, DKIM)
    # ------------------------------------------------------------------

    async def check_dns_email_security(self, base_url: str) -> List[WebAppVulnerability]:
        vulns: List[WebAppVulnerability] = []
        domain = self._base_domain(base_url)
        if not domain:
            return vulns

        import socket as _socket

        def _txt(name: str) -> List[str]:
            try:
                import dns.resolver  # type: ignore
                answers = dns.resolver.resolve(name, "TXT", lifetime=5)
                return [b.decode() for rdata in answers for b in rdata.strings]
            except Exception:
                try:
                    results = _socket.getaddrinfo(name, None)
                    return []
                except Exception:
                    return []

        loop = asyncio.get_event_loop()

        # SPF
        try:
            txts = await loop.run_in_executor(None, _txt, domain)
            spf = [t for t in txts if t.startswith("v=spf1")]
            if not spf:
                vulns.append(self._v("MISSING_SPF", MEDIUM, base_url, "SPF",
                    f"No SPF TXT record found for '{domain}'.",
                    "Add an SPF record to prevent email spoofing: 'v=spf1 include:... -all'.", "dns"))
            else:
                for record in spf:
                    if record.strip().endswith("+all") or record.strip().endswith("?all"):
                        vulns.append(self._v("WEAK_SPF", MEDIUM, base_url, "SPF",
                            f"SPF record ends with permissive qualifier: {record[:80]}",
                            "Use '-all' (fail) or '~all' (softfail) instead of '+all' or '?all'.", "dns"))
        except Exception:
            pass

        # DMARC
        try:
            dmarc_txts = await loop.run_in_executor(None, _txt, f"_dmarc.{domain}")
            dmarc = [t for t in dmarc_txts if t.startswith("v=DMARC1")]
            if not dmarc:
                vulns.append(self._v("MISSING_DMARC", MEDIUM, base_url, "DMARC",
                    f"No DMARC TXT record found for '_dmarc.{domain}'.",
                    "Add a DMARC record to enable email authentication reporting: 'v=DMARC1; p=reject; rua=mailto:...'.", "dns"))
            else:
                record = dmarc[0]
                if "p=none" in record:
                    vulns.append(self._v("WEAK_DMARC", LOW, base_url, "DMARC",
                        f"DMARC policy is 'none' (monitoring only): {record[:80]}",
                        "Upgrade DMARC policy to 'quarantine' or 'reject' to prevent spoofed emails from being delivered.", "dns"))
        except Exception:
            pass

        return vulns

    # ------------------------------------------------------------------
    # Robots.txt / sitemap analysis
    # ------------------------------------------------------------------

    async def check_robots(self, base_url: str, client: httpx.AsyncClient, allow_private: bool = False) -> List[WebAppVulnerability]:
        vulns: List[WebAppVulnerability] = []
        robots_url = f"{base_url.rstrip('/')}/robots.txt"
        try:
            r = await self._safe_get(robots_url, client, allow_private=allow_private)
            if r is None or r.status_code != 200:
                return vulns
            text = r.text
            disallowed = re.findall(r"(?i)disallow:\s*(/\S+)", text)
            sensitive = [
                p for p in disallowed
                if any(kw in p.lower() for kw in (
                    "admin", "config", "backup", "private", "secret",
                    "internal", "staging", "test", "debug", "phpmyadmin",
                ))
            ]
            if sensitive:
                vulns.append(self._v("ROBOTS_SENSITIVE_PATHS", INFO, robots_url, None,
                    f"robots.txt disallows potentially sensitive paths: {', '.join(sensitive[:5])}",
                    "Do not rely on robots.txt to protect sensitive content; use proper authentication/authorisation.", "access-control"))
        except Exception:
            pass
        return vulns

    # ------------------------------------------------------------------
    # Result builder
    # ------------------------------------------------------------------

    def _build_result(
        self,
        target: str,
        pages: List[CrawlResult],
        vulns: List[WebAppVulnerability],
        base_url: str = "",
        scan_duration: float = 0.0,
        error: Optional[str] = None,
        fp: Optional[TechFingerprint] = None,
    ) -> WebAppScanResult:
        counts: Dict[str, int] = {CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0}
        for v in vulns:
            counts[v.severity.lower()] = counts.get(v.severity.lower(), 0) + 1
        if not base_url:
            base_url = pages[0].url if pages else target
        fp_dict = None
        if fp:
            fp_dict = {
                "cms": fp.cms,
                "framework": fp.framework,
                "server": fp.server,
                "languages": fp.languages,
                "libraries": fp.libraries,
                "login_paths": fp.login_paths,
            }
        return WebAppScanResult(
            target=target, base_url=base_url, pages_crawled=len(pages),
            vulnerabilities=vulns,
            total_vulns=len(vulns),
            critical_count=counts[CRITICAL], high_count=counts[HIGH],
            medium_count=counts[MEDIUM], low_count=counts[LOW], info_count=counts[INFO],
            scan_duration=scan_duration, fingerprint=fp_dict, error=error,
        )

    # ------------------------------------------------------------------
    # Main scan entry point
    # ------------------------------------------------------------------

    async def scan(self, target: str, allow_private: bool = False) -> WebAppScanResult:
        from cybersec.config.settings import settings
        from cybersec.core.tools.port_scanner import _is_scan_target_allowed  # lazy import

        t0 = time.perf_counter()
        self.visited_urls.clear()

        base_url = target if target.startswith("http") else f"https://{target}"
        http_fallback = base_url.replace("https://", "http://", 1)

        # SSRF guard: resolve host IP before opening any connection
        if not allow_private:
            ip = self._resolve_ip(base_url)
            if ip is None or not _is_scan_target_allowed(ip):
                return WebAppScanResult(
                    target=target, base_url=base_url, pages_crawled=0,
                    vulnerabilities=[], total_vulns=0,
                    critical_count=0, high_count=0, medium_count=0, low_count=0, info_count=0,
                    scan_duration=time.perf_counter() - t0,
                    fingerprint=None,
                    error="Scanning private, loopback, or cloud-metadata addresses is not permitted",
                )

        all_vulns: List[WebAppVulnerability] = []
        crawl_error: Optional[str] = None
        pages: List[CrawlResult] = []
        fp: Optional[TechFingerprint] = None

        async def _do_scan() -> None:
            nonlocal pages, crawl_error, fp

            async with httpx.AsyncClient(
                timeout=self.timeout,
                verify=False,
                headers={"User-Agent": "Mozilla/5.0 (compatible; CyberSec-Scanner/2.0)"},
                follow_redirects=False,
            ) as client:
                # Crawl
                try:
                    pages = await self.crawl(base_url, client, allow_private=allow_private)
                except Exception as exc:
                    crawl_error = str(exc)

                if not pages and not target.startswith("http"):
                    _fb = http_fallback
                    self.visited_urls.clear()
                    try:
                        pages = await self.crawl(_fb, client, allow_private=allow_private)
                        crawl_error = None
                        # update base_url used below
                        nonlocal_base[0] = _fb
                    except Exception as exc:
                        crawl_error = str(exc)

                _base = nonlocal_base[0]

                # Fingerprint from crawl data
                if pages:
                    fp = self.fingerprint(pages, _base)

                # Run all passive/non-injection checks concurrently
                passive = await asyncio.gather(
                    self.check_tls(_base),
                    self.check_headers(_base, client, allow_private=allow_private),
                    self.check_cors(_base, client, allow_private=allow_private),
                    self.check_exposed_files(_base, client),
                    self.check_admin_panels(_base, client, allow_private=allow_private),
                    self.check_http_methods(_base, client, allow_private=allow_private),
                    self.check_open_redirect(_base, client),
                    self.check_robots(_base, client, allow_private=allow_private),
                    self.check_dns_email_security(_base),
                    self.check_path_traversal(_base, client, allow_private=allow_private),
                    self.check_directory_listing(pages),
                    return_exceptions=True,
                )
                for r in passive:
                    if isinstance(r, list):
                        all_vulns.extend(r)

                # Form-based injection checks on each crawled page
                form_tasks = []
                for page in pages:
                    if page.forms:
                        form_tasks += [
                            self.check_sqli(page.url, page.forms, client, allow_private=allow_private),
                            self.check_xss(page.url, page.forms, client, allow_private=allow_private),
                            self.check_csrf(page.url, page.forms),
                            self.check_ssti(page.url, page.forms, client, allow_private=allow_private),
                        ]
                    if "?" in page.url and not page.forms:
                        form_tasks.append(self.check_xss(page.url, [], client, allow_private=allow_private))

                if form_tasks:
                    for r in await asyncio.gather(*form_tasks, return_exceptions=True):
                        if isinstance(r, list):
                            all_vulns.extend(r)

        # nonlocal_base is a mutable container so the inner coroutine can update base_url
        nonlocal_base = [base_url]

        timeout_error: Optional[str] = None
        try:
            await asyncio.wait_for(
                _do_scan(),
                timeout=settings.WEBAPP_SCAN_MAX_DURATION_SECONDS,
            )
        except asyncio.TimeoutError:
            timeout_error = (
                "Scan exceeded the maximum allowed duration and was stopped early; "
                "results may be incomplete."
            )

        base_url = nonlocal_base[0]

        # Scan note if nothing found
        if not pages and not all_vulns:
            all_vulns.append(self._v("SCAN_NOTE", INFO, base_url, None,
                "No pages crawled. Site may block automated requests or require authentication.",
                "Try increasing max_pages or verify the target is accessible.", ""))

        # Deduplicate and sort
        seen: set = set()
        unique: List[WebAppVulnerability] = []
        for v in all_vulns:
            key = (v.vuln_type, v.url, v.parameter)
            if key not in seen:
                seen.add(key)
                unique.append(v)
        unique.sort(key=lambda v: _SEV_RANK.get(v.severity.lower(), 5))

        final_error = timeout_error or crawl_error

        return self._build_result(
            target=target, pages=pages, vulns=unique,
            base_url=base_url, scan_duration=time.perf_counter() - t0,
            error=final_error, fp=fp,
        )
