import asyncio
import httpx
from dataclasses import dataclass

@dataclass
class SecurityHeaderAnalysis:
    header: str
    present: bool
    value: str | None
    severity: str
    recommendation: str

@dataclass
class HTTPHeadersResult:
    target: str
    url: str
    status_code: int | None
    headers: dict[str, str]
    security_analysis: list[SecurityHeaderAnalysis]
    server: str | None
    powered_by: str | None
    error: str | None

SECURITY_HEADERS = [
    {"name": "Strict-Transport-Security", "severity": "HIGH", "recommendation": "Add HSTS header"},
    {"name": "Content-Security-Policy", "severity": "HIGH", "recommendation": "Add CSP header"},
    {"name": "X-Frame-Options", "severity": "MEDIUM", "recommendation": "Add X-Frame-Options: DENY"},
    {"name": "X-Content-Type-Options", "severity": "MEDIUM", "recommendation": "Add X-Content-Type-Options: nosniff"},
    {"name": "Referrer-Policy", "severity": "LOW", "recommendation": "Add Referrer-Policy header"},
    {"name": "Permissions-Policy", "severity": "LOW", "recommendation": "Add Permissions-Policy header"},
    {"name": "X-XSS-Protection", "severity": "LOW", "recommendation": "X-XSS-Protection is deprecated"}
]

async def check_http_headers(target: str, path: str = "/") -> HTTPHeadersResult:
    url = target if target.startswith("http") else f"https://{target}"
    url = url.rstrip("/") + path
    
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=True, verify=False) as client:
            resp = await client.get(url)
            
        headers_dict = dict(resp.headers)
        
        analysis = []
        for sh in SECURITY_HEADERS:
            hname = sh["name"]
            found_key = next((k for k in headers_dict.keys() if k.lower() == hname.lower()), None)
            if found_key:
                analysis.append(SecurityHeaderAnalysis(
                    header=hname, present=True, value=headers_dict[found_key],
                    severity=sh["severity"], recommendation=sh["recommendation"]
                ))
            else:
                analysis.append(SecurityHeaderAnalysis(
                    header=hname, present=False, value=None,
                    severity=sh["severity"], recommendation=sh["recommendation"]
                ))
                
        server = headers_dict.get("Server", headers_dict.get("server"))
        powered_by = headers_dict.get("X-Powered-By", headers_dict.get("x-powered-by"))
        
        return HTTPHeadersResult(
            target=target,
            url=url,
            status_code=resp.status_code,
            headers=headers_dict,
            security_analysis=analysis,
            server=server,
            powered_by=powered_by,
            error=None
        )
            
    except Exception as e:
        return HTTPHeadersResult(target, url, None, {}, [], None, None, str(e))
