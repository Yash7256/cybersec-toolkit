import dataclasses
import logging
from typing import Optional

import httpx

from cybersec.core.utils import RateLimiter

logger = logging.getLogger(__name__)


@dataclasses.dataclass(slots=True)
class GeoResult:
    ip: str
    country: Optional[str] = None
    country_code: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    lat: Optional[float] = None
    lon: Optional[float] = None
    isp: Optional[str] = None
    org: Optional[str] = None
    timezone: Optional[str] = None
    asn: Optional[str] = None
    is_private: bool = False
    error: Optional[str] = None


class GeoTool:
    def __init__(self) -> None:
        self._rate_limiter = RateLimiter(rate=30, per_seconds=60)

    async def lookup(self, ip: str) -> GeoResult:
        result = GeoResult(ip=ip)

        try:
            import ipaddress

            addr = ipaddress.ip_address(ip)
            if addr.is_private or addr.is_loopback or addr.is_reserved:
                result.is_private = True
                return result
        except ValueError:
            result.error = f"Invalid IP address: {ip}"
            return result

        await self._rate_limiter.acquire()

        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(5.0)) as client:
                response = await client.get(f"http://ip-api.com/json/{ip}")

                if response.status_code == 429:
                    result.error = "Rate limit exceeded. Please wait before making more requests."
                    return result

                if response.status_code != 200:
                    result.error = f"API returned status code {response.status_code}"
                    return result

                data = response.json()

                if data.get("status") == "fail":
                    result.error = data.get("message", "Unknown API error")
                    return result

                result.country = data.get("country")
                result.country_code = data.get("countryCode")
                result.region = data.get("regionName")
                result.city = data.get("city")
                result.lat = data.get("lat")
                result.lon = data.get("lon")
                result.isp = data.get("isp")
                result.org = data.get("org")
                result.timezone = data.get("timezone")
                result.asn = data.get("as")

        except httpx.TimeoutException:
            result.error = "Request timeout"
        except Exception as e:
            logger.warning(f"GeoIP lookup failed for {ip}: {type(e).__name__}: {e}")
            result.error = str(e)

        return result
