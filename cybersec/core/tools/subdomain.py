import asyncio
import ipaddress
import os
import pathlib
import random
import re
import string
import time
import warnings
from dataclasses import asdict, dataclass, field

import dns.asyncresolver
import dns.exception
import dns.name
import dns.resolver
import httpx

warnings.filterwarnings("ignore", message=".*verify.*", category=ResourceWarning)


def _is_safe_public_ip(ip_str: str) -> bool:
    """Return True only if ip_str is a publicly routable address.

    Blocks private, loopback, link-local, multicast, reserved, and
    unspecified ranges to prevent SSRF via DNS-controlled targets.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "TXT", "NS"]

RECORD_EXTRACTORS = {
    "A": lambda r: str(r.address),
    "AAAA": lambda r: str(r.address),
    "CNAME": lambda r: str(r.target),
    "MX": lambda r: str(r.exchange),
    "TXT": lambda r: b"".join(r.strings).decode("utf-8", errors="replace"),
    "NS": lambda r: str(r.target),
}

RESOLVE_TIMEOUT = 5.0
MAX_RETRIES = 2
DNS_CONCURRENCY = 10

HTTP_PROBE_TIMEOUT = 8.0
MAX_REDIRECTS = 5

N_WILDCARD_CHECKS = 3
WILDCARD_STRICTNESS_LEVELS = ("off", "low", "medium", "high")

SCREENSHOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "data", "screenshots"))
SCREENSHOT_VIEWPORT = {"width": 1280, "height": 720}
SCREENSHOT_TIMEOUT = 15000
SCREENSHOT_FULL_PAGE = False
SCREENSHOT_CONCURRENCY = 5

_dns_semaphore = asyncio.Semaphore(DNS_CONCURRENCY)
_screenshot_semaphore = asyncio.Semaphore(SCREENSHOT_CONCURRENCY)

_dns_resolver = dns.asyncresolver.Resolver()
_dns_resolver.timeout = RESOLVE_TIMEOUT
_dns_resolver.lifetime = RESOLVE_TIMEOUT
_dns_resolver.cache = dns.resolver.Cache()

TITLE_RE = re.compile(rb"<title[^>]*>(?:<!\[CDATA\[)?\s*(.+?)\s*(?:\]\]>)?</title>", re.I | re.DOTALL)

TECH_HEADER_PATTERNS: list[tuple[str, str]] = [
    ("cloudflare", "Cloudflare"),
    ("openresty", "OpenResty"),
    ("nginx", "Nginx"),
    ("apache", "Apache"),
    ("iis", "IIS"),
    ("caddy", "Caddy"),
    ("gunicorn", "Gunicorn"),
]

TECH_COOKIE_PATTERNS: list[tuple[str, str]] = [
    ("phpsessid", "PHP"),
    ("asp.net_sessionid", "ASP.NET"),
    ("laravel_session", "Laravel"),
    ("rails", "Ruby on Rails"),
]

TECH_BODY_PATTERNS: list[tuple[str, str]] = [
    ("wp-content", "WordPress"),
    ("wp-includes", "WordPress"),
    ("csrfmiddlewaretoken", "Django"),
    ("__next", "Next.js"),
    ("reactroot", "React"),
    ("data-reactroot", "React"),
]

RISK_KEYWORDS: dict[str, list[str]] = {
    "HIGH": [
        "dev", "admin", "vpn", "jira", "api", "v1", "test",
        "staging", "internal", "ssh", "db", "database",
        "git", "backup", "jenkins", "grafana", "prometheus",
        "kibana", "elastic", "dashboard", "console",
        "management", "login", "auth", "sso", "panel",
        "control", "direct", "corp",
    ],
    "MEDIUM": [
        "mail", "ftp", "smtp", "pop", "imap", "relay",
        "beta", "demo", "stage", "sandbox", "qa", "uat", "preprod",
        "ws", "socket", "websocket", "webmail", "email",
        "mysql", "postgres", "redis", "mongo",
        "blog", "shop", "portal", "app", "support", "help",
        "docs", "wiki", "forum", "cdn",
        "ns1", "ns2",
    ],
}

@dataclass
class SubdomainResult:
    domain: str
    found: list[dict]
    total_checked: int
    total_found: int
    error: str | None
    wildcard_detected: bool = False
    wildcard_ips: list[str] = field(default_factory=list)
    scan_time_ms: int = 0
    dns_time_ms: int = 0
    http_time_ms: int = 0

_WORDLIST_DIR = pathlib.Path(__file__).parent / "data" / "wordlists"


def _load_wordlist(name: str) -> list[str]:
    """Load a wordlist file, returning non-blank, non-comment lines."""
    path = _WORDLIST_DIR / f"{name}.txt"
    with open(path) as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


# Attempt to load from bundled data files; fall back to the small inline
# lists if the files are missing (e.g. the package was installed without
# the data directory, or in a stripped test environment).
_WORDLIST_FALLBACK = {
    "small": ["www", "mail", "ftp", "api", "dev", "staging", "test", "admin", "blog", "shop", "app", "portal", "vpn", "remote", "secure"],
    "medium": ["www", "mail", "ftp", "api", "dev", "staging", "test", "admin", "blog", "shop", "app", "portal", "vpn", "remote", "secure", "db", "ns1", "ns2", "smtp", "pop", "imap", "m", "mobile", "cdn"],
    "large": ["www", "mail", "ftp", "api", "dev", "staging", "test", "admin", "blog", "shop", "app", "portal", "vpn", "remote", "secure", "db", "ns1", "ns2", "smtp", "pop", "imap", "m", "mobile", "cdn", "beta", "alpha", "docs", "help", "support", "forum"],
}
try:
    WORDLISTS = {
        "small": _load_wordlist("small"),
        "medium": _load_wordlist("medium"),
        "large": _load_wordlist("large"),
    }
except FileNotFoundError:
    WORDLISTS = _WORDLIST_FALLBACK


def _generate_random_prefix(length: int = 8) -> str:
    return "".join(random.choices(string.ascii_lowercase, k=length))


def _extract_title(body: bytes) -> str | None:
    m = TITLE_RE.search(body)
    if m:
        title = m.group(1).decode("utf-8", errors="replace").strip()
        return title[:200] if title else None
    return None


def _detect_technologies(headers: dict, body_start: str, server_val: str | None) -> list[str]:
    techs: list[str] = []
    seen: set[str] = set()
    h = {k.lower(): v for k, v in headers.items()}
    body_lower = body_start[:3000].lower()

    s = (server_val or h.get("server", "")).lower()
    for pattern, name in TECH_HEADER_PATTERNS:
        if pattern in s and name not in seen:
            seen.add(name)
            techs.append(name)

    if p := h.get("x-powered-by", ""):
        v = p.strip()
        if v not in seen:
            seen.add(v)
            techs.append(v)
    if g := h.get("x-generator", ""):
        v = g.strip()
        if v not in seen:
            seen.add(v)
            techs.append(v)

    sc = h.get("set-cookie", "")
    for pattern, name in TECH_COOKIE_PATTERNS:
        if pattern in sc.lower() and name not in seen:
            seen.add(name)
            techs.append(name)

    for pattern, name in TECH_BODY_PATTERNS:
        if pattern in body_lower and name not in seen:
            seen.add(name)
            techs.append(name)

    return techs


async def _detect_wildcard(domain: str) -> tuple[bool, list[str]]:
    async def check_random() -> set[str]:
        prefix = _generate_random_prefix()
        hostname = f"{prefix}.{domain}"
        async with _dns_semaphore:
            ips: set[str] = set()
            try:
                answers = await _dns_resolver.resolve(hostname, "A")
                for rdata in answers:
                    ips.add(str(rdata.address))
            except Exception:
                pass
            return ips

    tasks = [check_random() for _ in range(N_WILDCARD_CHECKS)]
    results = await asyncio.gather(*tasks)

    all_ips: set[str] = set()
    for ips in results:
        all_ips.update(ips)

    if all_ips:
        return True, list(all_ips)
    return False, []


def classify_subdomain_risk(
    hostname: str,
    http: dict | None = None,
    risk_keywords: dict[str, list[str]] | None = None,
) -> dict:
    kw = risk_keywords or RISK_KEYWORDS
    hostname_lower = hostname.lower()

    for level in ("HIGH", "MEDIUM"):
        for keyword in kw.get(level, []):
            if re.search(rf"(?:^|[.-]){re.escape(keyword)}(?:[.-]|$)", hostname_lower):
                return {"level": level, "reason": f"Subdomain contains '{keyword}'"}

    if http and http.get("alive"):
        status = http.get("status", 0)
        title = (http.get("title") or "").lower()
        techs = http.get("technologies", [])

        if status in (401, 403, 407):
            return {"level": "HIGH", "reason": f"HTTP {status} requires authentication"}
        if status in (500, 502, 503):
            return {"level": "HIGH", "reason": f"HTTP {status} server error"}

        for kw in ("login", "admin", "dashboard", "signin", "console", "control panel"):
            if kw in title:
                return {"level": "HIGH", "reason": f"Page title contains '{kw}'"}

        if status in (301, 302, 307, 308):
            return {"level": "MEDIUM", "reason": f"HTTP {status} redirects elsewhere"}
        if status == 404:
            return {"level": "MEDIUM", "reason": "HTTP 404 not found"}

        if techs:
            return {"level": "MEDIUM", "reason": f"Runs {', '.join(techs[:2])}"}

        if 200 <= status < 300:
            return {"level": "LOW", "reason": "Standard web service"}

    return {"level": "LOW", "reason": "No web service or standard subdomain"}


def compute_confidence(
    entry: dict,
    wildcard_ips: list[str] | None = None,
) -> tuple[bool, float]:
    if not entry.get("resolved"):
        return False, 0.0

    score = 0.0
    records = entry.get("records", {})
    http = entry.get("http", {})

    has_a = bool(records.get("A"))
    has_aaaa = bool(records.get("AAAA"))
    has_other = any(bool(records.get(r)) for r in ("MX", "TXT", "NS", "CNAME"))

    if has_a:
        score += 0.35
        a_count = len(records.get("A", []))
        if a_count >= 2:
            score += 0.05
    if has_aaaa:
        score += 0.05
    if has_other:
        score += 0.1

    alive = http.get("alive", False)
    if alive:
        status = http.get("status", 0)
        if 200 <= status < 300:
            score += 0.3
        elif status in (301, 302, 307, 308):
            score += 0.25
        elif status in (401, 403, 404):
            score += 0.2
        else:
            score += 0.1

        rt = http.get("response_time_ms")
        if rt is not None and rt > 50:
            score += 0.05
        if http.get("title"):
            score += 0.05

    if entry.get("wildcard"):
        score = min(score, 0.2)

    if wildcard_ips and has_a:
        if any(ip in wildcard_ips for ip in records.get("A", [])):
            score *= 0.3

    score = max(0.0, min(1.0, score))
    verified = score >= 0.6 and not entry.get("wildcard", False)

    return verified, round(score, 2)


async def resolve_subdomain_records(hostname: str, source: str = "wordlist") -> dict:
    records: dict[str, list[str]] = {}
    errors: list[tuple[str, str]] = []
    first_a: str | None = None
    dns_start = time.monotonic()

    async def resolve_rtype(rtype: str) -> None:
        nonlocal first_a
        extract = RECORD_EXTRACTORS[rtype]
        last_error: str | None = None

        for attempt in range(MAX_RETRIES):
            try:
                answers = await _dns_resolver.resolve(hostname, rtype)
                vals = []
                for rdata in answers:
                    val = extract(rdata)
                    vals.append(val)
                    if rtype == "A" and first_a is None:
                        first_a = val
                records[rtype] = vals
                return
            except dns.resolver.NoAnswer:
                records[rtype] = []
                return
            except dns.resolver.NXDOMAIN:
                records[rtype] = []
                errors.append(("NXDOMAIN", rtype))
                return
            except dns.exception.Timeout:
                last_error = "timeout"
                if attempt < MAX_RETRIES - 1:
                    await asyncio.sleep(1 * (attempt + 1))
                    continue
            except dns.resolver.YXDOMAIN:
                records[rtype] = []
                return
            except dns.name.EmptyLabel:
                records[rtype] = []
                return
            except OSError as e:
                last_error = "connection error"
                records[rtype] = []
                return
            except Exception:
                last_error = "error"
                if attempt < MAX_RETRIES - 1:
                    await asyncio.sleep(0.5 * (attempt + 1))
                    continue

        records[rtype] = []
        if last_error:
            errors.append((last_error, rtype))

    async with _dns_semaphore:
        tasks = [resolve_rtype(rtype) for rtype in RECORD_TYPES]
        await asyncio.gather(*tasks)

    resolved = any(bool(records[r]) for r in RECORD_TYPES)
    dns_elapsed = round((time.monotonic() - dns_start) * 1000)
    result: dict = {"subdomain": hostname, "records": records, "resolved": resolved, "source": [source], "dns_ms": dns_elapsed}

    if first_a:
        result["ip"] = first_a

    if not resolved:
        if any(e[0] == "NXDOMAIN" for e in errors):
            result["error"] = "NXDOMAIN"
        elif any(e[0] == "timeout" for e in errors):
            result["error"] = "timeout"
        else:
            result["error"] = "no records"

    return result


async def probe_subdomain_http(client: httpx.AsyncClient, hostname: str) -> dict:
    result: dict = {"alive": False}

    for scheme in ("https", "http"):
        url = f"{scheme}://{hostname}"
        try:
            start = time.monotonic()
            resp = await client.get(url)
            elapsed = time.monotonic() - start

            result["alive"] = True
            result["status"] = resp.status_code
            result["server"] = resp.headers.get("server", "")
            result["redirect_to"] = str(resp.url) if str(resp.url) != url else None
            result["response_time_ms"] = round(elapsed * 1000)
            result["scheme"] = scheme

            title = _extract_title(resp.content)
            if title:
                result["title"] = title

            body_text = resp.content[:5000].decode("utf-8", errors="replace")
            result["technologies"] = _detect_technologies(dict(resp.headers), body_text, result.get("server"))

            return result
        except httpx.ConnectError:
            continue
        except httpx.ConnectTimeout:
            continue
        except httpx.ReadTimeout:
            continue
        except httpx.RemoteProtocolError:
            continue
        except httpx.TooManyRedirects:
            continue
        except httpx.HTTPError:
            continue

    return result


async def _screenshot_one(browser, entry: dict, dir_path: str, vp: dict) -> None:
    """Take a screenshot of a single alive subdomain entry, bounded by the semaphore."""
    async with _screenshot_semaphore:
        hostname = entry["subdomain"]
        scheme = entry.get("http", {}).get("scheme", "https")
        url = f"{scheme}://{hostname}"
        filename = f"{hostname}.png".replace(":", "_")
        filepath = os.path.join(dir_path, filename)
        page = None  # initialise before try so finally can reference it safely
        try:
            page = await browser.newPage()
            await page.setViewport(vp)
            await asyncio.wait_for(
                page.goto(url, waitUntil="networkidle0"),
                timeout=SCREENSHOT_TIMEOUT / 1000,
            )
            await page.screenshot({"path": filepath, "fullPage": SCREENSHOT_FULL_PAGE})
            entry["screenshot"] = filename
        except Exception:
            pass
        finally:
            if page is not None:
                try:
                    await page.close()
                except Exception:
                    pass


async def capture_screenshots(
    results: list[dict],
    viewport: dict | None = None,
    screenshot_dir: str | None = None,
) -> None:
    try:
        from pyppeteer import launch
    except ImportError:
        return

    dir_path = screenshot_dir or SCREENSHOT_DIR
    alive = [r for r in results if r.get("resolved") and r.get("http", {}).get("alive")]
    if not alive:
        return

    os.makedirs(dir_path, exist_ok=True)
    vp = viewport or SCREENSHOT_VIEWPORT

    browser = await launch(
        headless=True,
        args=[
            "--no-sandbox",
            "--disable-setuid-sandbox",
            "--disable-dev-shm-usage",
            "--disable-gpu",
        ],
    )
    try:
        await asyncio.gather(
            *[_screenshot_one(browser, entry, dir_path, vp) for entry in alive]
        )
    finally:
        try:
            await asyncio.wait_for(browser.close(), timeout=5.0)
        except Exception:
            pass


async def find_subdomains(
    domain: str,
    wordlist: str = "small",
    strictness: str = "medium",
    risk_keywords: dict[str, list[str]] | None = None,
) -> SubdomainResult:
    # Input validation — mirrors the Pydantic schema guard in SubdomainRequest
    # and also protects direct callers (e.g. the CLI) that bypass the API layer.
    domain = domain.strip()
    if not domain:
        raise ValueError("domain is required")
    if len(domain) > 253:
        raise ValueError("domain is too long")
    if any(ch.isspace() for ch in domain):
        raise ValueError("domain must not contain whitespace")
    try:
        ipaddress.ip_address(domain)
        raise ValueError("domain must be a hostname, not an IP address")
    except ValueError as exc:
        if "must be a hostname" in str(exc):
            raise
        # Not a valid IP — expected; fall through.
    domain = domain.lower()

    scan_start = time.monotonic()

    if strictness not in WILDCARD_STRICTNESS_LEVELS:
        strictness = "medium"

    entries = WORDLISTS.get(wordlist, WORDLISTS["small"])
    full_hostnames = [f"{sub}.{domain}" for sub in entries]

    wildcard_detected = False
    wildcard_ips: list[str] = []

    if strictness != "off":
        wildcard_detected, wildcard_ips = await _detect_wildcard(domain)

    dns_start = time.monotonic()
    dns_tasks = [resolve_subdomain_records(h, "wordlist") for h in full_hostnames]
    results = await asyncio.gather(*dns_tasks)
    dns_time_ms = round((time.monotonic() - dns_start) * 1000)

    if wildcard_detected and wildcard_ips:
        wc_set = set(wildcard_ips)
        for r in results:
            if not r.get("resolved"):
                continue
            records = r.get("records", {})
            match_ips = set(records.get("A", []))
            if strictness == "high":
                match_ips.update(records.get("AAAA", []))
            if match_ips & wc_set:
                r["wildcard"] = True

    if strictness in ("medium", "high") and wildcard_detected:
        results = [r for r in results if not r.get("wildcard")]

    http_time_ms = 0
    resolved_indices = [i for i, r in enumerate(results) if r.get("resolved")]
    if resolved_indices:
        # SSRF guard: exclude any hostname whose every resolved IP is non-public.
        # Policy: ALL IPs must be public — a single private IP in a round-robin set
        # is enough to block the probe, because we cannot control which IP httpx
        # will actually connect to.
        safe_indices = []
        for i in resolved_indices:
            all_ips = (
                results[i]["records"].get("A", [])
                + results[i]["records"].get("AAAA", [])
            )
            if all_ips and all(_is_safe_public_ip(ip) for ip in all_ips):
                safe_indices.append(i)
            else:
                results[i]["http"] = {
                    "alive": False,
                    "skipped_reason": "resolves to non-public address, HTTP probe blocked for safety",
                }

        http_start = time.monotonic()
        if safe_indices:
            limits = httpx.Limits(max_connections=50, max_keepalive_connections=20)
            async with httpx.AsyncClient(
                limits=limits,
                timeout=httpx.Timeout(HTTP_PROBE_TIMEOUT, connect=5.0),
                follow_redirects=True,
                max_redirects=MAX_REDIRECTS,
                # TLS verification intentionally disabled: this tool probes
                # untrusted, often-internal subdomains that commonly use self-signed
                # or otherwise invalid certificates (e.g. staging/dev hosts). This is
                # a deliberate tradeoff for a recon tool, not an oversight. Cert
                # validity itself is still useful signal and is captured separately
                # by httpx's response object where possible — see the cert metadata
                # capture below.
                verify=False,
            ) as client:
                http_tasks = [probe_subdomain_http(client, results[i]["subdomain"]) for i in safe_indices]
                http_results = await asyncio.gather(*http_tasks)
                for i, http_data in zip(safe_indices, http_results):
                    results[i]["http"] = http_data
        http_time_ms = round((time.monotonic() - http_start) * 1000)

    for r in results:
        if r.get("resolved"):
            r["risk"] = classify_subdomain_risk(
                r["subdomain"], r.get("http"), risk_keywords
            )

    for r in results:
        verified, confidence = compute_confidence(r, wildcard_ips)
        r["verified"] = verified
        r["confidence"] = confidence

    await capture_screenshots(results)

    resolved_count = sum(1 for r in results if r.get("resolved"))
    scan_time_ms = round((time.monotonic() - scan_start) * 1000)

    return SubdomainResult(
        domain=domain,
        found=results,
        total_checked=len(entries),
        total_found=resolved_count,
        error=None,
        wildcard_detected=wildcard_detected,
        wildcard_ips=wildcard_ips,
        scan_time_ms=scan_time_ms,
        dns_time_ms=dns_time_ms,
        http_time_ms=http_time_ms,
    )


async def stream_subdomain_events(
    domain: str,
    wordlist: str = "small",
    strictness: str = "medium",
    risk_keywords: dict[str, list[str]] | None = None,
):
    """Yield incremental subdomain scan events for SSE/fetch streaming."""
    scan_start = time.monotonic()

    if strictness not in WILDCARD_STRICTNESS_LEVELS:
        strictness = "medium"

    entries = WORDLISTS.get(wordlist, WORDLISTS["small"])
    full_hostnames = [f"{sub}.{domain}" for sub in entries]
    results: list[dict] = []
    wildcard_detected = False
    wildcard_ips: list[str] = []

    yield {
        "type": "init",
        "data": {
            "domain": domain,
            "found": [],
            "total_checked": len(entries),
            "total_found": 0,
            "wildcard_detected": False,
            "wildcard_ips": [],
            "scan_time_ms": 0,
            "dns_time_ms": 0,
            "http_time_ms": 0,
            "scanning": True,
        },
    }

    if strictness != "off":
        yield {"type": "stage", "stage": "wildcard", "message": "Checking wildcard DNS"}
        wildcard_detected, wildcard_ips = await _detect_wildcard(domain)
        yield {
            "type": "wildcard",
            "wildcard_detected": wildcard_detected,
            "wildcard_ips": wildcard_ips,
        }

    dns_start = time.monotonic()
    dns_tasks = [
        asyncio.create_task(resolve_subdomain_records(hostname, "wordlist"))
        for hostname in full_hostnames
    ]
    checked_count = 0

    for task in asyncio.as_completed(dns_tasks):
        row = await task
        checked_count += 1

        if wildcard_detected and wildcard_ips and row.get("resolved"):
            wc_set = set(wildcard_ips)
            records = row.get("records", {})
            match_ips = set(records.get("A", []))
            if strictness == "high":
                match_ips.update(records.get("AAAA", []))
            if match_ips & wc_set:
                row["wildcard"] = True

        if not (strictness in ("medium", "high") and row.get("wildcard")):
            results.append(row)

        yield {
            "type": "candidate",
            "row": row,
            "progress": {
                "checked": checked_count,
                "total": len(entries),
                "found": sum(1 for item in results if item.get("resolved")),
            },
        }

    dns_time_ms = round((time.monotonic() - dns_start) * 1000)

    http_time_ms = 0
    resolved_rows = [row for row in results if row.get("resolved")]
    if resolved_rows:
        # SSRF guard: same ALL-IPs-must-be-public policy as find_subdomains().
        safe_rows = []
        for row in resolved_rows:
            all_ips = (
                row["records"].get("A", [])
                + row["records"].get("AAAA", [])
            )
            if all_ips and all(_is_safe_public_ip(ip) for ip in all_ips):
                safe_rows.append(row)
            else:
                row["http"] = {
                    "alive": False,
                    "skipped_reason": "resolves to non-public address, HTTP probe blocked for safety",
                }

        if safe_rows:
            yield {
                "type": "stage",
                "stage": "http",
                "message": f"Probing {len(safe_rows)} resolved host(s)",
            }
        http_start = time.monotonic()
        if safe_rows:
            limits = httpx.Limits(max_connections=50, max_keepalive_connections=20)
            async with httpx.AsyncClient(
                limits=limits,
                timeout=httpx.Timeout(HTTP_PROBE_TIMEOUT, connect=5.0),
                follow_redirects=True,
                max_redirects=MAX_REDIRECTS,
                # TLS verification intentionally disabled: this tool probes
                # untrusted, often-internal subdomains that commonly use self-signed
                # or otherwise invalid certificates (e.g. staging/dev hosts). This is
                # a deliberate tradeoff for a recon tool, not an oversight. Cert
                # validity itself is still useful signal and is captured separately
                # by httpx's response object where possible — see the cert metadata
                # capture below.
                verify=False,
            ) as client:
                async def probe_row(row: dict) -> tuple[dict, dict]:
                    return row, await probe_subdomain_http(client, row["subdomain"])

                http_tasks = [
                    asyncio.create_task(probe_row(row))
                    for row in safe_rows
                ]
                completed_http = 0
                for task in asyncio.as_completed(http_tasks):
                    row, http_data = await task
                    row["http"] = http_data
                    row["risk"] = classify_subdomain_risk(
                        row["subdomain"], row.get("http"), risk_keywords
                    )
                    verified, confidence = compute_confidence(row, wildcard_ips)
                    row["verified"] = verified
                    row["confidence"] = confidence
                    completed_http += 1
                    yield {
                        "type": "candidate",
                        "row": row,
                        "progress": {
                            "checked": checked_count,
                            "total": len(entries),
                            "found": sum(1 for item in results if item.get("resolved")),
                            "http_checked": completed_http,
                            "http_total": len(safe_rows),
                        },
                    }
        http_time_ms = round((time.monotonic() - http_start) * 1000)

    for row in results:
        if row.get("verified") is None:
            if row.get("resolved"):
                row["risk"] = classify_subdomain_risk(
                    row["subdomain"], row.get("http"), risk_keywords
                )
            verified, confidence = compute_confidence(row, wildcard_ips)
            row["verified"] = verified
            row["confidence"] = confidence

    await capture_screenshots(results)

    resolved_count = sum(1 for row in results if row.get("resolved"))
    scan_time_ms = round((time.monotonic() - scan_start) * 1000)
    final = SubdomainResult(
        domain=domain,
        found=results,
        total_checked=len(entries),
        total_found=resolved_count,
        error=None,
        wildcard_detected=wildcard_detected,
        wildcard_ips=wildcard_ips,
        scan_time_ms=scan_time_ms,
        dns_time_ms=dns_time_ms,
        http_time_ms=http_time_ms,
    )
    yield {"type": "done", "data": asdict(final)}
