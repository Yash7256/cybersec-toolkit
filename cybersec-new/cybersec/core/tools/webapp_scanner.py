import asyncio
import httpx
import re
from dataclasses import dataclass
from typing import List, Set, Dict, Optional

@dataclass
class WebAppVulnerability:
    vuln_type: str
    severity: str
    url: str
    parameter: Optional[str]
    evidence: Optional[str]
    recommendation: str

@dataclass
class CrawlResult:
    url: str
    status_code: int
    content_type: Optional[str]
    forms: List[dict]
    links: List[str]

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
    scan_duration: float
    error: Optional[str]

class WebAppScanner:
    SENSITIVE_FILES = [
        ".env", ".git/config", "robots.txt", "sitemap.xml",
        "wp-config.php", "config.php", ".htaccess",
        "phpinfo.php", "admin/", "backup.zip", "database.sql",
        "web.config", ".DS_Store", "package.json", "yarn.lock"
    ]

    SQLI_PAYLOADS = [
        "'", "''", "' OR '1'='1", "' OR 1=1--",
        "\" OR \"1\"=\"1", "1; DROP TABLE users--",
        "' UNION SELECT NULL--", "admin'--"
    ]

    XSS_PAYLOADS = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
        "<svg onload=alert(1)>",
        "'\"><script>alert(1)</script>"
    ]

    SECURITY_HEADERS_REQUIRED = {
        "Strict-Transport-Security": "HIGH",
        "Content-Security-Policy": "HIGH",
        "X-Frame-Options": "MEDIUM",
        "X-Content-Type-Options": "MEDIUM",
        "Referrer-Policy": "LOW"
    }

    SQL_ERRORS = [
        "sql syntax", "mysql_fetch", "ORA-", "syntax error",
        "unclosed quotation", "quoted string not properly terminated",
        "pg_query", "sqlite_", "Microsoft OLE DB"
    ]

    def __init__(self, max_pages: int = 20, timeout: float = 10.0):
        self.max_pages = max_pages
        self.timeout = timeout
        self.visited_urls: Set[str] = set()

    async def crawl(self, base_url: str, client: httpx.AsyncClient) -> List[CrawlResult]:
        queue = [base_url]
        results = []
        domain = base_url.split("//")[-1].split("/")[0]

        while queue and len(self.visited_urls) < self.max_pages:
            url = queue.pop(0)
            if url in self.visited_urls:
                continue
            self.visited_urls.add(url)

            try:
                response = await client.get(url, follow_redirects=True)
                text = response.text

                # Extract links
                href_pattern = r'href=["\'](https?://[^"\']+|/[^"\']*|[^"\'/][^"\']*\.html)[^"\']*["\']'
                raw_links = re.findall(href_pattern, text)
                links = []
                for link in raw_links:
                    if link.startswith("http"):
                        if domain in link:
                            links.append(link)
                    elif link.startswith("/"):
                        links.append(f"{base_url.rstrip('/')}{link}")
                    else:
                        path = url.rsplit("/", 1)[0]
                        links.append(f"{path}/{link}")

                for l in links:
                    if l not in self.visited_urls and l not in queue:
                        queue.append(l)

                # Extract forms
                form_pattern = r'<form[^>]*action=["\']([^"\']*)["\'][^>]*method=["\']([^"\']*)["\']'
                forms_raw = re.findall(form_pattern, text, re.IGNORECASE)
                
                # We need to refine form parsing to get inputs. Since we can't easily parse nested html with regex accurately, we'll do a simple approximation.
                forms = []
                # Finding all forms to get their inputs
                form_blocks = re.split(r'<form', text, flags=re.IGNORECASE)[1:]
                for block in form_blocks:
                    # try to extract action and method from the opening tag
                    tag_end = block.find('>')
                    if tag_end == -1: continue
                    open_tag = block[:tag_end]
                    
                    m_action = re.search(r'action=["\']([^"\']*)["\']', open_tag, re.IGNORECASE)
                    m_method = re.search(r'method=["\']([^"\']*)["\']', open_tag, re.IGNORECASE)
                    
                    action = m_action.group(1) if m_action else url
                    if action.startswith("/"):
                        action = f"{base_url.rstrip('/')}{action}"
                    elif not action.startswith("http"):
                        # Relative URL
                        path = url.rsplit("/", 1)[0]
                        action = f"{path}/{action}"
                        
                    method = m_method.group(1).upper() if m_method else "GET"
                    
                    # Extract inputs from form body till `</form>`
                    form_body = block.split('</form>', 1)[0]
                    input_names = re.findall(r'<string name=["\']([^"\']*)["\']', form_body, re.IGNORECASE)
                    input_names += re.findall(r'<input[^>]*name=["\']([^"\']*)["\']', form_body, re.IGNORECASE)
                    input_names += re.findall(r'<select[^>]*name=["\']([^"\']*)["\']', form_body, re.IGNORECASE)
                    input_names += re.findall(r'<textarea[^>]*name=["\']([^"\']*)["\']', form_body, re.IGNORECASE)
                    
                    if input_names:
                        forms.append({
                            "action": action,
                            "method": method,
                            "inputs": list(set(input_names))
                        })

                results.append(CrawlResult(
                    url=url,
                    status_code=response.status_code,
                    content_type=response.headers.get("content-type"),
                    forms=forms,
                    links=links
                ))
            except Exception:
                continue

        return results

    async def check_sqli(self, url: str, forms: List[dict], client: httpx.AsyncClient) -> List[WebAppVulnerability]:
        vulns = []
        for form in forms:
            for input_name in form["inputs"]:
                for i, payload in enumerate(self.SQLI_PAYLOADS[:3]): # Max 3 payloads per input
                    try:
                        data = {k: "test" for k in form["inputs"]}
                        data[input_name] = payload
                        if form["method"] == "POST":
                            resp = await client.post(form["action"], data=data, follow_redirects=True)
                        else:
                            resp = await client.get(form["action"], params=data, follow_redirects=True)
                            
                        # Check response
                        matching_error = None
                        for sql_err in self.SQL_ERRORS:
                            if sql_err.lower() in resp.text.lower():
                                matching_error = sql_err
                                break
                                
                        if matching_error:
                            error_snippet = matching_error
                            # Find surrounding context of error for evidence
                            # A simple approach: grab matching error snippet
                            idx = resp.text.lower().find(matching_error.lower())
                            snippet = resp.text[max(0, idx-20):idx+80]
                            
                            vulns.append(WebAppVulnerability(
                                vuln_type="SQLi",
                                severity="CRITICAL",
                                url=url,
                                parameter=input_name,
                                evidence=snippet[:100],
                                recommendation="Use parameterized queries / prepared statements"
                            ))
                            break # Found SQLi, don't need to try more payloads for this input
                    except Exception:
                        pass
        return vulns

    async def check_xss(self, url: str, forms: List[dict], client: httpx.AsyncClient) -> List[WebAppVulnerability]:
        vulns = []
        for form in forms:
            for input_name in form["inputs"]:
                for payload in self.XSS_PAYLOADS[:2]: # Limit to 2 payloads per input
                    try:
                        data = {k: "test" for k in form["inputs"]}
                        data[input_name] = payload
                        if form["method"] == "POST":
                            resp = await client.post(form["action"], data=data, follow_redirects=True)
                        else:
                            resp = await client.get(form["action"], params=data, follow_redirects=True)
                            
                        if payload in resp.text:
                            vulns.append(WebAppVulnerability(
                                vuln_type="XSS",
                                severity="HIGH",
                                url=url,
                                parameter=input_name,
                                evidence=f"Payload reflected: {payload[:50]}",
                                recommendation="Encode all user output. Implement CSP."
                            ))
                            break
                    except Exception:
                        pass
        return vulns

    async def check_csrf(self, url: str, forms: List[dict]) -> List[WebAppVulnerability]:
        vulns = []
        for form in forms:
            if form["method"] == "POST":
                has_token = False
                for inp in form["inputs"]:
                    if any(t in inp.lower() for t in ["csrf", "token", "_token", "authenticity_token", "nonce"]):
                        has_token = True
                        break
                if not has_token:
                    vulns.append(WebAppVulnerability(
                        vuln_type="CSRF",
                        severity="MEDIUM",
                        url=url,
                        parameter=None,
                        evidence="POST form has no CSRF token field",
                        recommendation="Add CSRF token to all state-changing forms"
                    ))
        return vulns

    async def check_cors(self, url: str, client: httpx.AsyncClient) -> List[WebAppVulnerability]:
        vulns = []
        try:
            resp = await client.options(url, headers={"Origin": "https://evil.com"}, follow_redirects=True)
            allow_origin = resp.headers.get("Access-Control-Allow-Origin")
            allow_creds = resp.headers.get("Access-Control-Allow-Credentials")
            
            if allow_origin == "*":
                vulns.append(WebAppVulnerability(
                    vuln_type="CORS",
                    severity="HIGH",
                    url=url,
                    parameter=None,
                    evidence="Access-Control-Allow-Origin: *",
                    recommendation="Restrict Access-Control-Allow-Origin to trusted domains"
                ))
            elif allow_origin == "https://evil.com":
                sev = "CRITICAL" if allow_creds == "true" else "HIGH"
                vulns.append(WebAppVulnerability(
                    vuln_type="CORS",
                    severity=sev,
                    url=url,
                    parameter=None,
                    evidence=f"Reflects arbitrary origin. Allow-Credentials: {allow_creds}",
                    recommendation="Do not dynamically set Access-Control-Allow-Origin from Origin header"
                ))
        except Exception:
            pass
        return vulns

    async def check_missing_headers(self, url: str, client: httpx.AsyncClient) -> List[WebAppVulnerability]:
        vulns = []
        try:
            resp = await client.get(url, follow_redirects=True)
            for header, severity in self.SECURITY_HEADERS_REQUIRED.items():
                # Case insensitive check
                if header.lower() not in [h.lower() for h in resp.headers.keys()]:
                    vulns.append(WebAppVulnerability(
                        vuln_type="MISSING_HEADER",
                        severity=severity,
                        url=url,
                        parameter=header,
                        evidence=f"Header '{header}' is not set",
                        recommendation=f"Add {header} response header"
                    ))
        except Exception as e:
            vulns.append(WebAppVulnerability(
                vuln_type="REQUEST_FAILED",
                severity="INFO",
                url=url,
                parameter=None,
                evidence=str(e),
                recommendation="Verify the site is reachable and does not block automated scanners"
            ))
        return vulns

    async def check_exposed_files(self, base_url: str, client: httpx.AsyncClient) -> List[WebAppVulnerability]:
        vulns = []
        
        async def check_file(path: str):
            try:
                target_url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
                resp = await client.get(target_url, follow_redirects=False)
                if resp.status_code in (200, 301, 302):
                    sev = "HIGH" if path in [".env", ".git/config", "wp-config.php"] else "MEDIUM"
                    vulns.append(WebAppVulnerability(
                        vuln_type="EXPOSED_FILE",
                        severity=sev,
                        url=target_url,
                        parameter=None,
                        evidence=f"File accessible: HTTP {resp.status_code}",
                        recommendation=f"Restrict access to {path}"
                    ))
            except Exception as e:
                vulns.append(WebAppVulnerability(
                    vuln_type="REQUEST_FAILED",
                    severity="INFO",
                    url=target_url,
                    parameter=None,
                    evidence=str(e),
                    recommendation="Verify accessibility of target"
                ))
                
        await asyncio.gather(*(check_file(p) for p in self.SENSITIVE_FILES))
        return vulns

    async def _create_client(self):
        return httpx.AsyncClient(
            timeout=self.timeout,
            verify=False,
            headers={"User-Agent": "CyberSec-Scanner/1.0"},
            follow_redirects=True
        )

    def _build_result(self, target: str, pages: List[CrawlResult], vulns: List[WebAppVulnerability]) -> WebAppScanResult:
        import time
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for v in vulns:
            severity_counts[v.severity] += 1
        
        base_url = pages[0].url.split("//")[-1].split("/")[0] if pages else target
        if not base_url.startswith("http"):
            base_url = f"https://{base_url}"
        
        return WebAppScanResult(
            target=target,
            base_url=base_url,
            pages_crawled=len(pages),
            vulnerabilities=vulns,
            total_vulns=len(vulns),
            critical_count=severity_counts["CRITICAL"],
            high_count=severity_counts["HIGH"],
            medium_count=severity_counts["MEDIUM"],
            low_count=severity_counts["LOW"],
            scan_duration=0,
            error=None
        )

    async def scan(self, target: str) -> WebAppScanResult:
        import time
        start_time = time.perf_counter()
        # Prefer HTTPS but fall back to HTTP if HTTPS fails or yields no pages
        base_url_https = target if target.startswith("http") else f"https://{target}"
        base_url_http = target if target.startswith("http") else f"http://{target}"
        base_url = base_url_https
        self.visited_urls.clear()
        
        all_vulns = []
        crawl_error = None

        async with httpx.AsyncClient(
            timeout=self.timeout,
            verify=False,
            headers={"User-Agent": "CyberSec-Scanner/1.0"},
            follow_redirects=True
        ) as client:
            try:
                pages = await self.crawl(base_url, client)
            except Exception as e:
                pages = []
                crawl_error = str(e)

            # Retry with HTTP if HTTPS crawl produced nothing
            if not pages and not target.startswith("http"):
                base_url = base_url_http
                try:
                    pages = await self.crawl(base_url, client)
                    crawl_error = None
                except Exception as e:
                    crawl_error = str(e)
            
            # Always run header/CORS/exposed-file checks on the base URL we ended up using
            res2 = await asyncio.gather(
                self.check_missing_headers(base_url, client),
                self.check_cors(base_url, client),
                self.check_exposed_files(base_url, client),
                return_exceptions=True
            )
            for r in res2:
                if isinstance(r, list):
                    all_vulns.extend(r)
            
            if not pages and not all_vulns:
                all_vulns.append(WebAppVulnerability(
                    vuln_type="SCAN_NOTE",
                    severity="INFO",
                    url=base_url,
                    parameter=None,
                    evidence="No pages crawled; site may block the crawler or returned no HTML pages",
                    recommendation="Try increasing max_pages or ensure the target allows GET requests"
                ))
            
            # Form-based checks require crawled pages
            for page in pages:
                if page.forms:
                    res3 = await asyncio.gather(
                        self.check_sqli(page.url, page.forms, client),
                        self.check_xss(page.url, page.forms, client),
                        self.check_csrf(page.url, page.forms),
                        return_exceptions=True
                    )
                    for r in res3:
                        if isinstance(r, list):
                            all_vulns.extend(r)

        # Deduplicate
        seen = set()
        unique_vulns = []
        for v in all_vulns:
            key = (v.vuln_type, v.url, v.parameter)
            if key not in seen:
                seen.add(key)
                unique_vulns.append(v)
                
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for v in unique_vulns:
            severity_counts[v.severity] += 1
            
        return WebAppScanResult(
            target=target,
            base_url=base_url,
            pages_crawled=len(pages),
            vulnerabilities=unique_vulns,
            total_vulns=len(unique_vulns),
            critical_count=severity_counts["CRITICAL"],
            high_count=severity_counts["HIGH"],
            medium_count=severity_counts["MEDIUM"],
            low_count=severity_counts["LOW"],
            scan_duration=time.perf_counter() - start_time,
            error=crawl_error
        )
