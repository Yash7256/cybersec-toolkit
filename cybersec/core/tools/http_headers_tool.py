import dataclasses
import logging
import time
from typing import Optional

logger = logging.getLogger(__name__)


@dataclasses.dataclass(slots=True)
class HTTPHeadersResult:
    url: str
    final_url: Optional[str] = None
    status_code: Optional[int] = None
    redirect_chain: list[str] = dataclasses.field(default_factory=list)
    headers: dict[str, str] = dataclasses.field(default_factory=dict)
    security_headers: dict[str, Optional[str]] = dataclasses.field(default_factory=dict)
    server: Optional[str] = None
    x_powered_by: Optional[str] = None
    response_time_ms: float = 0.0
    error: Optional[str] = None


class HTTPHeadersTool:
    SECURITY_HEADER_NAMES = {
        "content-security-policy": "Content-Security-Policy",
        "strict-transport-security": "Strict-Transport-Security",
        "x-frame-options": "X-Frame-Options",
        "x-content-type-options": "X-Content-Type-Options",
        "x-xss-protection": "X-XSS-Protection",
        "referrer-policy": "Referrer-Policy",
        "permissions-policy": "Permissions-Policy",
        "x-permitted-cross-domain-policies": "X-Permitted-Cross-Domain-Policies",
        "cross-origin-embedder-policy": "Cross-Origin-Embedder-Policy",
        "cross-origin-opener-policy": "Cross-Origin-Opener-Policy",
        "cross-origin-resource-policy": "Cross-Origin-Resource-Policy",
    }

    async def inspect(self, url: str) -> HTTPHeadersResult:
        result = HTTPHeadersResult(url=url)

        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        start_time = time.monotonic()

        try:
            import httpx

            async with httpx.AsyncClient(
                timeout=httpx.Timeout(10.0, connect=5.0),
                follow_redirects=True,
                redirects=False,
                headers={
                    "User-Agent": "Cybersec-Scanner/1.0 (Security Analysis Tool)"
                },
            ) as client:
                redirect_chain = [url]
                current_url = url
                max_redirects = 5
                redirect_count = 0

                while redirect_count < max_redirects:
                    try:
                        response = await client.get(current_url, timeout=5.0)
                        result.status_code = response.status_code
                        result.final_url = str(response.url)
                        result.headers = dict(response.headers)

                        for header_name in response.headers:
                            if header_name.lower() == "server":
                                result.server = response.headers[header_name]
                            elif header_name.lower() == "x-powered-by":
                                result.x_powered_by = response.headers[header_name]

                        if 300 <= response.status_code < 400 and "location" in response.headers:
                            redirect_count += 1
                            next_url = response.headers["location"]
                            if not next_url.startswith(("http://", "https://")):
                                from urllib.parse import urljoin
                                next_url = urljoin(current_url, next_url)
                            current_url = next_url
                            redirect_chain.append(next_url)
                        else:
                            break

                    except httpx.TimeoutException:
                        result.error = "Request timeout"
                        break
                    except httpx.RedirectError as e:
                        result.error = f"Redirect error: {e}"
                        break

            result.redirect_chain = redirect_chain

            for key, name in self.SECURITY_HEADER_NAMES.items():
                found = None
                for header_name, header_value in result.headers.items():
                    if header_name.lower() == key:
                        found = header_value
                        break
                result.security_headers[name] = found

        except ImportError:
            result.error = "httpx not installed"
        except Exception as e:
            logger.warning(f"HTTP headers check failed for {url}: {type(e).__name__}: {e}")
            result.error = str(e)

        result.response_time_ms = round((time.monotonic() - start_time) * 1000, 2)
        return result
