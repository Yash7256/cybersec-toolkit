import time
from dataclasses import dataclass, field
from urllib.parse import urlparse

import httpx


@dataclass
class SecurityHeaderAnalysis:
    header: str
    present: bool
    value: str | None
    severity: str
    recommendation: str
    description: str
    strength: str


@dataclass
class CookieAnalysis:
    name: str
    secure: bool
    httponly: bool
    samesite: str | None
    risk: str
    issues: list[str] = field(default_factory=list)


@dataclass
class HTTPHeadersResult:
    target: str
    url: str
    final_url: str | None
    status_code: int | None
    protocol: str | None
    response_time_ms: float | None
    response_time_rating: str | None
    headers: dict[str, str]
    security_headers: dict
    security_analysis: list[SecurityHeaderAnalysis]
    technologies: list[str]
    cdn: str | None
    waf: str | None
    cookies: list[CookieAnalysis]
    risk_score: int | None
    risk_level: str | None
    security_score: int | None
    server: str | None
    powered_by: str | None
    compression: dict
    caching: dict
    cors: dict
    csp: dict
    clickjacking: dict
    information_disclosure: list[dict]
    redirect_chain: list[dict]
    allowed_methods: list[str]
    dangerous_methods: list[str]
    api_detection: list[str]
    cloud_provider: str | None
    compliance: dict
    timeline: list[dict]
    recommendations: list[str]
    ai_summary: str | None
    tls_verification_skipped: bool = True
    error: str | None = None


SECURITY_HEADERS = [
    {
        "name": "Strict-Transport-Security",
        "severity": "HIGH",
        "recommendation": "Add HSTS with max-age of at least 31536000 seconds and includeSubDomains where appropriate.",
        "description": "Forces browsers to use HTTPS for future requests.",
    },
    {
        "name": "Content-Security-Policy",
        "severity": "HIGH",
        "recommendation": "Add a Content-Security-Policy that restricts scripts, objects, frames, and trusted origins.",
        "description": "Reduces XSS, data injection, clickjacking, and content injection risk.",
    },
    {
        "name": "X-Frame-Options",
        "severity": "MEDIUM",
        "recommendation": "Add X-Frame-Options: DENY or SAMEORIGIN, or enforce frame-ancestors in CSP.",
        "description": "Protects against clickjacking in older browsers.",
    },
    {
        "name": "X-Content-Type-Options",
        "severity": "MEDIUM",
        "recommendation": "Add X-Content-Type-Options: nosniff.",
        "description": "Prevents MIME-sniffing of scripts and styles.",
    },
    {
        "name": "Referrer-Policy",
        "severity": "LOW",
        "recommendation": "Add Referrer-Policy: strict-origin-when-cross-origin or stricter.",
        "description": "Controls how much referrer data leaks to other origins.",
    },
    {
        "name": "Permissions-Policy",
        "severity": "LOW",
        "recommendation": "Add Permissions-Policy to disable unused browser capabilities.",
        "description": "Limits access to sensitive browser APIs.",
    },
]


TECH_PATTERNS: dict[str, tuple[str, ...]] = {
    "Cloudflare": ("cloudflare", "cf-ray", "cf-cache-status"),
    "nginx": ("nginx",),
    "Apache": ("apache",),
    "Express": ("express", "x-powered-by: express"),
    "Next.js": ("next.js", "x-nextjs", "x-vercel-cache", "__next"),
    "Vercel": ("vercel", "x-vercel"),
    "PHP": ("php", "x-powered-by: php"),
    "ASP.NET": ("asp.net", "x-aspnet-version", "x-powered-by: asp.net"),
    "Django": ("django", "csrftoken"),
    "Laravel": ("laravel", "laravel_session"),
    "WordPress": ("wordpress", "wp-", "x-pingback"),
    "Akamai": ("akamai", "akamai-cache-status", "x-akamai"),
    "Fastly": ("fastly", "x-served-by", "x-cache-hits"),
    "Amazon CloudFront": ("cloudfront", "x-amz-cf-id", "x-amz-cf-pop"),
}


WAF_PATTERNS: dict[str, tuple[str, ...]] = {
    "Cloudflare WAF": ("cloudflare", "cf-ray", "__cf_bm", "cf-chl"),
    "Akamai WAF": ("akamai", "akamai-ghost", "akamai-bot"),
    "Imperva WAF": ("imperva", "incap_ses", "visid_incap"),
    "AWS WAF": ("awselb", "awsalb", "x-amzn", "cloudfront"),
    "Fastly WAF": ("fastly", "x-served-by", "x-fastly"),
}


CDN_PATTERNS: dict[str, tuple[str, ...]] = {
    "Cloudflare": ("cloudflare", "cf-ray", "cf-cache-status"),
    "Akamai": ("akamai", "akamai-cache-status"),
    "Fastly": ("fastly", "x-served-by"),
    "Amazon CloudFront": ("cloudfront", "x-amz-cf-id", "x-amz-cf-pop"),
    "Vercel Edge Network": ("vercel", "x-vercel"),
    "Netlify Edge": ("netlify", "x-nf-request-id"),
}


def _normalize_target(target: str, path: str) -> str:
    base = target.strip()
    if not base.startswith(("http://", "https://")):
        base = f"https://{base}"
    parsed_path = path or "/"
    if not parsed_path.startswith("/"):
        parsed_path = f"/{parsed_path}"
    parsed = urlparse(base)
    if parsed.path and parsed.path != "/":
        return base
    return base.rstrip("/") + parsed_path


def _header(headers: dict[str, str], name: str) -> str | None:
    return headers.get(name.lower())


def _detect_from_patterns(headers: dict[str, str], cookies: list[str], patterns: dict[str, tuple[str, ...]]) -> str | None:
    haystack = " ".join(
        [
            " ".join(f"{key}: {value}" for key, value in headers.items()),
            " ".join(cookies),
        ]
    ).lower()
    for label, needles in patterns.items():
        if any(needle in haystack for needle in needles):
            return label
    return None


def _detect_technologies(headers: dict[str, str], cookies: list[str]) -> list[str]:
    haystack = " ".join(
        [
            " ".join(f"{key}: {value}" for key, value in headers.items()),
            " ".join(cookies),
        ]
    ).lower()
    tech = [name for name, needles in TECH_PATTERNS.items() if any(needle in haystack for needle in needles)]
    return sorted(set(tech))


def _analyze_security_headers(headers: dict[str, str]) -> tuple[dict, list[SecurityHeaderAnalysis]]:
    present = []
    missing = []
    analysis = []
    for item in SECURITY_HEADERS:
        name = item["name"]
        value = _header(headers, name)
        is_present = value is not None
        strength = "strong" if is_present else "missing"
        if name == "Strict-Transport-Security" and value:
            strength = _hsts_strength(value)["strength"]
        if name == "Content-Security-Policy" and value:
            strength = _csp_analysis(value)["strength"]

        row = {
            "header": name,
            "value": value,
            "severity": item["severity"],
            "recommendation": item["recommendation"],
            "description": item["description"],
            "strength": strength,
        }
        if is_present:
            present.append(row)
        else:
            missing.append(row)
        analysis.append(
            SecurityHeaderAnalysis(
                header=name,
                present=is_present,
                value=value,
                severity=item["severity"],
                recommendation=item["recommendation"],
                description=item["description"],
                strength=strength,
            )
        )
    return {"present": present, "missing": missing}, analysis


def _hsts_strength(value: str | None) -> dict:
    if not value:
        return {"enabled": False, "max_age": None, "include_subdomains": False, "preload": False, "strength": "missing", "issue": "HSTS is missing."}
    lower = value.lower()
    max_age = None
    for part in lower.split(";"):
        part = part.strip()
        if part.startswith("max-age="):
            try:
                max_age = int(part.split("=", 1)[1])
            except ValueError:
                max_age = None
    include_subdomains = "includesubdomains" in lower
    preload = "preload" in lower
    if max_age is None:
        strength = "weak"
        issue = "HSTS max-age is missing or invalid."
    elif max_age < 10886400:
        strength = "weak"
        issue = "HSTS duration is shorter than the common 18-week minimum."
    elif max_age < 31536000:
        strength = "moderate"
        issue = "HSTS is enabled but shorter than one year."
    else:
        strength = "strong"
        issue = None
    return {
        "enabled": True,
        "max_age": max_age,
        "include_subdomains": include_subdomains,
        "preload": preload,
        "strength": strength,
        "issue": issue,
    }


def _csp_analysis(value: str | None) -> dict:
    if not value:
        return {"enabled": False, "strength": "missing", "issues": ["Content-Security-Policy is missing."]}
    lower = value.lower()
    issues = []
    if "unsafe-inline" in lower:
        issues.append("Allows unsafe-inline scripts or styles.")
    if "unsafe-eval" in lower:
        issues.append("Allows unsafe-eval.")
    if "default-src" not in lower:
        issues.append("No default-src directive found.")
    if "frame-ancestors" not in lower:
        issues.append("No frame-ancestors directive for clickjacking protection.")
    strength = "strong" if not issues else "moderate" if len(issues) <= 2 else "weak"
    return {"enabled": True, "strength": strength, "issues": issues, "directives": [part.strip().split()[0] for part in value.split(";") if part.strip()]}


def _analyze_cookies(set_cookie_headers: list[str], scheme: str) -> list[CookieAnalysis]:
    cookies = []
    for raw in set_cookie_headers:
        parts = [part.strip() for part in raw.split(";") if part.strip()]
        if not parts:
            continue
        name = parts[0].split("=", 1)[0]
        attrs = {part.lower() for part in parts[1:]}
        secure = "secure" in attrs
        httponly = "httponly" in attrs
        samesite = next((part.split("=", 1)[1] for part in parts[1:] if part.lower().startswith("samesite=")), None)
        issues = []
        if scheme == "https" and not secure:
            issues.append("Secure flag missing.")
        if not httponly:
            issues.append("HttpOnly flag missing.")
        if not samesite:
            issues.append("SameSite attribute missing.")
        risk = "high" if len(issues) >= 2 else "medium" if issues else "low"
        cookies.append(CookieAnalysis(name=name, secure=secure, httponly=httponly, samesite=samesite, risk=risk, issues=issues))
    return cookies


def _compression(headers: dict[str, str]) -> dict:
    encoding = _header(headers, "content-encoding")
    if not encoding:
        return {"enabled": False, "type": None, "summary": "No response compression advertised."}
    enc = encoding.lower()
    if "br" in enc:
        kind = "Brotli"
    elif "gzip" in enc:
        kind = "gzip"
    elif "zstd" in enc:
        kind = "zstd"
    else:
        kind = encoding
    return {"enabled": True, "type": kind, "summary": f"{kind} compression enabled."}


def _cache_analysis(headers: dict[str, str]) -> dict:
    cache_control = _header(headers, "cache-control")
    etag = _header(headers, "etag")
    expires = _header(headers, "expires")
    cdn_cache = _header(headers, "cf-cache-status") or _header(headers, "x-cache") or _header(headers, "x-vercel-cache")
    if cdn_cache:
        summary = "CDN caching detected."
    elif cache_control:
        summary = "Application cache policy present."
    else:
        summary = "No explicit cache policy detected."
    return {
        "cache_control": cache_control,
        "etag": etag,
        "expires": expires,
        "cdn_cache_status": cdn_cache,
        "summary": summary,
    }


def _cors_analysis(headers: dict[str, str]) -> dict:
    origin = _header(headers, "access-control-allow-origin")
    credentials = _header(headers, "access-control-allow-credentials")
    methods = _header(headers, "access-control-allow-methods")
    issues = []
    if origin == "*":
        issues.append("Wildcard Access-Control-Allow-Origin allows any origin.")
    if origin == "*" and credentials and credentials.lower() == "true":
        issues.append("Wildcard origin with credentials is unsafe.")
    return {
        "enabled": origin is not None,
        "allow_origin": origin,
        "allow_credentials": credentials,
        "allow_methods": methods,
        "issues": issues,
        "risk": "high" if len(issues) > 1 else "medium" if issues else "low" if origin else "none",
    }


def _clickjacking(headers: dict[str, str], csp: dict) -> dict:
    xfo = _header(headers, "x-frame-options")
    csp_has_frame_ancestors = "frame-ancestors" in [directive.lower() for directive in csp.get("directives", [])]
    protected = bool(xfo or csp_has_frame_ancestors)
    return {
        "protected": protected,
        "x_frame_options": xfo,
        "frame_ancestors": csp_has_frame_ancestors,
        "summary": "Clickjacking protection present." if protected else "Clickjacking protection is missing.",
    }


def _information_disclosure(headers: dict[str, str]) -> list[dict]:
    findings = []
    for name in ("server", "x-powered-by", "x-aspnet-version", "x-generator", "x-runtime"):
        value = _header(headers, name)
        if value:
            severity = "medium" if any(char.isdigit() for char in value) or name != "server" else "low"
            findings.append({
                "header": name,
                "value": value,
                "severity": severity,
                "issue": f"{name} reveals implementation details.",
            })
    return findings


def _allowed_methods(headers: dict[str, str]) -> tuple[list[str], list[str]]:
    allow = _header(headers, "allow") or _header(headers, "access-control-allow-methods")
    methods = [method.strip().upper() for method in allow.split(",")] if allow else []
    dangerous = [method for method in methods if method in {"PUT", "DELETE", "TRACE", "CONNECT", "PATCH"}]
    return methods, dangerous


def _api_detection(headers: dict[str, str], url: str) -> list[str]:
    content_type = (_header(headers, "content-type") or "").lower()
    found = []
    if "application/json" in content_type:
        found.append("REST/JSON API")
    if "graphql" in url.lower() or "application/graphql" in content_type:
        found.append("GraphQL")
    if any(token in url.lower() for token in ("swagger", "openapi", "api-docs")):
        found.append("Swagger/OpenAPI")
    return found


def _cloud_provider(headers: dict[str, str], cdn: str | None) -> str | None:
    haystack = " ".join(f"{key}: {value}" for key, value in headers.items()).lower()
    if cdn == "Amazon CloudFront" or "x-amz" in haystack:
        return "AWS"
    if "x-azure" in haystack or "azure" in haystack:
        return "Microsoft Azure"
    if "google" in haystack or "gws" in haystack:
        return "Google Cloud"
    if cdn == "Vercel Edge Network":
        return "Vercel"
    if cdn == "Cloudflare":
        return "Cloudflare"
    return None


def _score_result(
    security_headers: dict,
    cookies: list[CookieAnalysis],
    disclosure: list[dict],
    cors: dict,
    dangerous_methods: list[str],
    csp: dict,
    hsts: dict,
) -> tuple[int, int, str, dict, list[str]]:
    penalty = 0
    recommendations = []
    for item in security_headers["missing"]:
        penalty += {"HIGH": 14, "MEDIUM": 9, "LOW": 5}.get(item["severity"], 5)
        recommendations.append(item["recommendation"])
    for cookie in cookies:
        penalty += 10 if cookie.risk == "high" else 5 if cookie.risk == "medium" else 0
        for issue in cookie.issues:
            recommendations.append(f"Set {issue.replace('.', '')} on cookie {cookie.name}.")
    if disclosure:
        penalty += min(15, 5 * len(disclosure))
        recommendations.append("Reduce server/framework version disclosure headers where possible.")
    if cors.get("risk") == "high":
        penalty += 18
        recommendations.append("Restrict CORS origins and avoid wildcard origin with credentials.")
    elif cors.get("risk") == "medium":
        penalty += 8
        recommendations.append("Review CORS policy and restrict allowed origins if possible.")
    if dangerous_methods:
        penalty += 15
        recommendations.append(f"Disable dangerous HTTP methods if not required: {', '.join(dangerous_methods)}.")
    if csp.get("strength") == "weak":
        penalty += 10
        recommendations.append("Strengthen Content-Security-Policy by removing unsafe directives and adding default-src/frame-ancestors.")
    if hsts.get("strength") == "weak":
        penalty += 8
        recommendations.append("Increase HSTS max-age and consider includeSubDomains.")

    risk_score = max(0, min(100, penalty))
    security_score = max(0, 100 - risk_score)
    risk_level = "Low" if risk_score < 30 else "Medium" if risk_score < 65 else "High"
    compliance = {
        "owasp_secure_headers": {
            "passed": len(security_headers["present"]),
            "total": len(SECURITY_HEADERS),
            "score": round((len(security_headers["present"]) / len(SECURITY_HEADERS)) * 100),
        },
        "mozilla_baseline": {
            "passed": sum(1 for item in security_headers["present"] if item["header"] in {"Strict-Transport-Security", "Content-Security-Policy", "X-Content-Type-Options", "Referrer-Policy"}),
            "total": 4,
        },
    }
    return risk_score, security_score, risk_level, compliance, list(dict.fromkeys(recommendations))


def _response_time_rating(ms: float | None) -> str | None:
    if ms is None:
        return None
    if ms <= 100:
        return "fast"
    if ms <= 500:
        return "moderate"
    return "slow"


def _redirect_chain(history: list[httpx.Response], final: httpx.Response) -> list[dict]:
    chain = []
    for resp in [*history, final]:
        chain.append({
            "url": str(resp.url),
            "status_code": resp.status_code,
            "location": resp.headers.get("location"),
        })
    return chain


def _timeline(response_time_ms: float | None, redirect_count: int) -> list[dict]:
    total = response_time_ms or 0
    return [
        {"step": "DNS", "status": "completed", "duration_ms": None},
        {"step": "TCP", "status": "completed", "duration_ms": None},
        {"step": "TLS", "status": "completed", "duration_ms": None},
        {"step": "Redirects", "status": "completed", "duration_ms": None, "count": redirect_count},
        {"step": "Headers Received", "status": "completed", "duration_ms": round(total, 2)},
    ]


def _summary(target: str, cdn: str | None, waf: str | None, protocol: str | None, score: int, missing_count: int, csp: dict) -> str:
    parts = [f"{target} responded over {protocol or 'HTTP'} with a web security score of {score}/100."]
    if cdn or waf:
        parts.append(f"Traffic appears protected by {waf or cdn}.")
    if missing_count:
        parts.append(f"{missing_count} recommended security header(s) are missing.")
    if csp.get("enabled") and csp.get("strength") != "strong":
        parts.append("The Content-Security-Policy exists but could be strengthened.")
    elif not csp.get("enabled"):
        parts.append("Content-Security-Policy is missing.")
    return " ".join(parts)


def _empty_result(target: str, url: str, error: str) -> "HTTPHeadersResult":
    return HTTPHeadersResult(
        target=target,
        url=url,
        final_url=None,
        status_code=None,
        protocol=None,
        response_time_ms=None,
        response_time_rating=None,
        headers={},
        security_headers={"present": [], "missing": []},
        security_analysis=[],
        technologies=[],
        cdn=None,
        waf=None,
        cookies=[],
        risk_score=None,
        risk_level=None,
        security_score=None,
        server=None,
        powered_by=None,
        compression={},
        caching={},
        cors={},
        csp={},
        clickjacking={},
        information_disclosure=[],
        redirect_chain=[],
        allowed_methods=[],
        dangerous_methods=[],
        api_detection=[],
        cloud_provider=None,
        compliance={},
        timeline=[],
        recommendations=[],
        ai_summary=None,
        tls_verification_skipped=True,
        error=error,
    )


def _resolve_host(url: str) -> str | None:
    """Return the resolved IP string for the host in *url*, or None on failure."""
    import socket
    host = urlparse(url).hostname
    if not host:
        return None
    try:
        return socket.getaddrinfo(host, None)[0][4][0]
    except OSError:
        return None


async def check_http_headers(target: str, path: str = "/", allow_private: bool = False) -> HTTPHeadersResult:
    url = _normalize_target(target, path)
    start = time.perf_counter()

    # --- SSRF guard: resolve the initial target and block private/loopback/metadata ---
    if not allow_private:
        from cybersec.core.tools.port_scanner import _is_scan_target_allowed  # lazy import
        ip = _resolve_host(url)
        if ip is None or not _is_scan_target_allowed(ip):
            return _empty_result(
                target, url,
                "Checking headers on private, loopback, or cloud-metadata addresses is not permitted",
            )

    _MAX_REDIRECTS = 5

    try:
        # verify=False is deliberate: we want to retrieve and report headers even for
        # sites with self-signed, expired, or otherwise misconfigured TLS certificates.
        # tls_verification_skipped=True is surfaced in the result so callers know the
        # certificate chain was not validated.
        async with httpx.AsyncClient(
            timeout=10,
            follow_redirects=False,  # we follow manually so we can re-validate each hop
            verify=False,            # see comment above
        ) as client:
            redirect_chain: list[dict] = []
            current_url = url
            resp = None

            for _ in range(_MAX_REDIRECTS + 1):
                resp = await client.get(current_url)
                redirect_chain.append({
                    "url": current_url,
                    "status_code": resp.status_code,
                    "location": resp.headers.get("location"),
                })
                if resp.status_code not in (301, 302, 303, 307, 308):
                    break
                location = resp.headers.get("location")
                if not location:
                    break
                # Resolve the redirect target relative to the current URL
                next_url = str(resp.url.copy_with()).rstrip("/")
                # httpx URL resolution
                next_url = str(httpx.URL(current_url).copy_with()).rstrip("/")
                next_url = location if location.startswith(("http://", "https://")) else str(httpx.URL(current_url).copy_with(path=location))
                # SSRF re-validation on each hop
                if not allow_private:
                    hop_ip = _resolve_host(next_url)
                    if hop_ip is None or not _is_scan_target_allowed(hop_ip):
                        return _empty_result(
                            target, url,
                            "Redirect chain led to a private, loopback, or cloud-metadata address; stopped following.",
                        )
                current_url = next_url

        response_time_ms = round((time.perf_counter() - start) * 1000, 2)
        headers_dict = {key.lower(): value for key, value in resp.headers.items()}
        raw_cookies = resp.headers.get_list("set-cookie")
        parsed_url = urlparse(str(resp.url))

        security_headers, security_analysis = _analyze_security_headers(headers_dict)
        cookies = _analyze_cookies(raw_cookies, parsed_url.scheme)
        technologies = _detect_technologies(headers_dict, raw_cookies)
        cdn = _detect_from_patterns(headers_dict, raw_cookies, CDN_PATTERNS)
        waf = _detect_from_patterns(headers_dict, raw_cookies, WAF_PATTERNS)
        hsts = _hsts_strength(_header(headers_dict, "strict-transport-security"))
        csp = _csp_analysis(_header(headers_dict, "content-security-policy"))
        compression = _compression(headers_dict)
        caching = _cache_analysis(headers_dict)
        cors = _cors_analysis(headers_dict)
        clickjacking = _clickjacking(headers_dict, csp)
        disclosure = _information_disclosure(headers_dict)
        allowed_methods, dangerous_methods = _allowed_methods(headers_dict)
        api_detection = _api_detection(headers_dict, str(resp.url))
        cloud_provider = _cloud_provider(headers_dict, cdn)
        risk_score, security_score, risk_level, compliance, recommendations = _score_result(
            security_headers,
            cookies,
            disclosure,
            cors,
            dangerous_methods,
            csp,
            hsts,
        )

        protocol = resp.http_version.replace("HTTP/", "HTTP/") if resp.http_version else None
        ai_summary = (
            _summary(target, cdn, waf, protocol, security_score, len(security_headers["missing"]), csp)
            + " Note: header data was retrieved without TLS certificate verification."
        )
        hop_count = len(redirect_chain) - 1  # hops before the final response

        return HTTPHeadersResult(
            target=target,
            url=url,
            final_url=str(resp.url),
            status_code=resp.status_code,
            protocol=protocol,
            response_time_ms=response_time_ms,
            response_time_rating=_response_time_rating(response_time_ms),
            headers=headers_dict,
            security_headers=security_headers,
            security_analysis=security_analysis,
            technologies=technologies,
            cdn=cdn,
            waf=waf,
            cookies=cookies,
            risk_score=risk_score,
            risk_level=risk_level,
            security_score=security_score,
            server=_header(headers_dict, "server"),
            powered_by=_header(headers_dict, "x-powered-by"),
            compression=compression,
            caching=caching,
            cors=cors,
            csp=csp,
            clickjacking=clickjacking,
            information_disclosure=disclosure,
            redirect_chain=redirect_chain,
            allowed_methods=allowed_methods,
            dangerous_methods=dangerous_methods,
            api_detection=api_detection,
            cloud_provider=cloud_provider,
            compliance=compliance,
            timeline=_timeline(response_time_ms, hop_count),
            recommendations=recommendations,
            ai_summary=ai_summary,
            tls_verification_skipped=True,
            error=None,
        )

    except Exception as e:
        return _empty_result(target, url, str(e))
