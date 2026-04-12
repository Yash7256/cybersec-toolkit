import asyncio
import httpx
from dataclasses import dataclass

@dataclass
class GeoIPResult:
    target: str
    ip: str | None
    country: str | None
    country_code: str | None
    region: str | None
    city: str | None
    lat: float | None
    lon: float | None
    isp: str | None
    org: str | None
    asn: str | None
    timezone: str | None
    error: str | None

async def geoip_lookup(target: str) -> GeoIPResult:
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                f"http://ip-api.com/json/{target}?fields=status,message,country,countryCode,region,city,lat,lon,isp,org,as,timezone,query"
            )
            data = resp.json()
            
            if data.get("status") == "fail":
                return GeoIPResult(
                    target=target, ip=None, country=None, country_code=None, region=None,
                    city=None, lat=None, lon=None, isp=None, org=None, asn=None, timezone=None,
                    error=data.get("message", "Failed to lookup")
                )
                
            return GeoIPResult(
                target=target,
                ip=data.get("query"),
                country=data.get("country"),
                country_code=data.get("countryCode"),
                region=data.get("region"),
                city=data.get("city"),
                lat=data.get("lat"),
                lon=data.get("lon"),
                isp=data.get("isp"),
                org=data.get("org"),
                asn=data.get("as"),
                timezone=data.get("timezone"),
                error=None
            )
    except Exception as e:
        return GeoIPResult(
            target=target, ip=None, country=None, country_code=None, region=None,
            city=None, lat=None, lon=None, isp=None, org=None, asn=None, timezone=None,
            error=str(e)
        )
