import asyncio
import socket
import time
from dataclasses import dataclass
from ipaddress import ip_address
from typing import Protocol

import httpx

from cybersec.config.settings import settings


@dataclass
class GeoIPResult:
    target: str
    ip: str | None
    resolved_ips: list[str]
    reverse_dns: str | None
    country: str | None
    country_code: str | None
    continent: str | None
    continent_code: str | None
    region: str | None
    city: str | None
    postal: str | None
    lat: float | None
    lon: float | None
    accuracy_radius: int | None
    map_url: str | None
    isp: str | None
    org: str | None
    asn: str | None
    asn_route: str | None
    asn_domain: str | None
    asn_type: str | None
    timezone: str | None
    local_time: str | None
    timezone_utc: str | None
    currency: str | None
    calling_code: str | None
    flag_emoji: str | None
    flag_image: str | None
    is_proxy: bool | None
    is_vpn: bool | None
    is_tor: bool | None
    is_hosting: bool | None
    is_mobile: bool | None
    threat_score: int | None
    abuse_contact: str | None
    cdn_provider: str | None
    is_cdn: bool
    infrastructure_note: str | None
    confidence: str
    location_accuracy: str | None
    rdap_name: str | None
    rdap_handle: str | None
    rdap_registry: str | None
    rdap_cidr: str | None
    rdap_country: str | None
    rdap_start_address: str | None
    rdap_end_address: str | None
    rdap_abuse_email: str | None
    rdap_abuse_phone: str | None
    rdap_events: list[dict]
    ip_results: list[dict]
    raw: dict | None
    provider: str
    cached: bool
    error: str | None

    @property
    def latitude(self) -> float | None:
        return self.lat

    @property
    def longitude(self) -> float | None:
        return self.lon

    @property
    def as_number(self) -> str | None:
        return self.asn


class GeoIPProvider(Protocol):
    name: str

    async def lookup(self, target: str) -> GeoIPResult:
        ...


class GeoIPError(Exception):
    pass


class IPWhoIsProvider:
    name = "ipwhois"

    async def lookup(self, target: str) -> GeoIPResult:
        url = f"https://ipwho.is/{target}"
        async with httpx.AsyncClient(timeout=settings.GEOIP_TIMEOUT) as client:
            resp = await client.get(url)

        if resp.status_code == 429:
            raise GeoIPError("GeoIP provider rate limit reached. Try again later.")
        resp.raise_for_status()
        data = resp.json()

        if data.get("success") is False:
            raise GeoIPError(data.get("message", "GeoIP lookup failed"))

        connection = data.get("connection") or {}
        timezone = data.get("timezone") or {}
        flag = data.get("flag") or {}
        security = data.get("security") or {}
        lat = data.get("latitude")
        lon = data.get("longitude")
        asn = f"AS{connection.get('asn')}" if connection.get("asn") else None

        return GeoIPResult(
            target=target,
            ip=data.get("ip"),
            resolved_ips=[],
            reverse_dns=None,
            country=data.get("country"),
            country_code=data.get("country_code"),
            continent=data.get("continent"),
            continent_code=data.get("continent_code"),
            region=data.get("region"),
            city=data.get("city"),
            postal=data.get("postal"),
            lat=lat,
            lon=lon,
            accuracy_radius=data.get("accuracy_radius"),
            map_url=f"https://www.google.com/maps/search/?api=1&query={lat},{lon}" if lat is not None and lon is not None else None,
            isp=connection.get("isp"),
            org=connection.get("org"),
            asn=asn,
            asn_route=connection.get("route"),
            asn_domain=connection.get("domain"),
            asn_type=connection.get("type"),
            timezone=timezone.get("id") if isinstance(timezone, dict) else timezone,
            local_time=timezone.get("current_time") if isinstance(timezone, dict) else None,
            timezone_utc=timezone.get("utc") if isinstance(timezone, dict) else None,
            currency=data.get("currency"),
            calling_code=data.get("calling_code"),
            flag_emoji=flag.get("emoji") if isinstance(flag, dict) else None,
            flag_image=flag.get("img") if isinstance(flag, dict) else None,
            is_proxy=security.get("proxy") if isinstance(security, dict) else None,
            is_vpn=security.get("vpn") if isinstance(security, dict) else None,
            is_tor=security.get("tor") if isinstance(security, dict) else None,
            is_hosting=security.get("hosting") if isinstance(security, dict) else None,
            is_mobile=security.get("mobile") if isinstance(security, dict) else connection.get("mobile"),
            threat_score=security.get("threat_score") if isinstance(security, dict) else None,
            abuse_contact=None,
            cdn_provider=None,
            is_cdn=False,
            infrastructure_note=None,
            confidence="medium",
            location_accuracy="city" if data.get("city") else None,
            rdap_name=None,
            rdap_handle=None,
            rdap_registry=None,
            rdap_cidr=None,
            rdap_country=None,
            rdap_start_address=None,
            rdap_end_address=None,
            rdap_abuse_email=None,
            rdap_abuse_phone=None,
            rdap_events=[],
            ip_results=[],
            raw=data,
            provider=self.name,
            cached=False,
            error=None,
        )


_PROVIDERS: dict[str, GeoIPProvider] = {
    "ipwhois": IPWhoIsProvider(),
}
_CACHE: dict[str, tuple[float, GeoIPResult]] = {}


def _empty_result(target: str, error: str, provider: str | None = None) -> GeoIPResult:
    return GeoIPResult(
        target=target,
        ip=None,
        resolved_ips=[],
        reverse_dns=None,
        country=None,
        country_code=None,
        continent=None,
        continent_code=None,
        region=None,
        city=None,
        postal=None,
        lat=None,
        lon=None,
        accuracy_radius=None,
        map_url=None,
        isp=None,
        org=None,
        asn=None,
        asn_route=None,
        asn_domain=None,
        asn_type=None,
        timezone=None,
        local_time=None,
        timezone_utc=None,
        currency=None,
        calling_code=None,
        flag_emoji=None,
        flag_image=None,
        is_proxy=None,
        is_vpn=None,
        is_tor=None,
        is_hosting=None,
        is_mobile=None,
        threat_score=None,
        abuse_contact=None,
        cdn_provider=None,
        is_cdn=False,
        infrastructure_note=None,
        confidence="low",
        location_accuracy=None,
        rdap_name=None,
        rdap_handle=None,
        rdap_registry=None,
        rdap_cidr=None,
        rdap_country=None,
        rdap_start_address=None,
        rdap_end_address=None,
        rdap_abuse_email=None,
        rdap_abuse_phone=None,
        rdap_events=[],
        ip_results=[],
        raw=None,
        provider=provider or settings.GEOIP_PROVIDER,
        cached=False,
        error=error,
    )


def _validate_target(target: str) -> str:
    normalized = target.strip()
    if not normalized:
        raise GeoIPError("Target is required")
    if len(normalized) > 253:
        raise GeoIPError("Target is too long")
    if any(ch.isspace() for ch in normalized):
        raise GeoIPError("Target must be a single IP address or hostname")

    try:
        parsed = ip_address(normalized)
    except ValueError:
        return normalized

    if not settings.GEOIP_ALLOW_PRIVATE_TARGETS and (
        parsed.is_private
        or parsed.is_loopback
        or parsed.is_link_local
        or parsed.is_multicast
        or parsed.is_reserved
        or parsed.is_unspecified
    ):
        raise GeoIPError("Private, local, reserved, or non-routable IPs are not sent to external GeoIP providers")
    return normalized


async def _resolve_target(target: str) -> tuple[str, list[str]]:
    try:
        ip_address(target)
        return target, [target]
    except ValueError:
        pass

    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(target, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise GeoIPError(f"Could not resolve hostname: {target}") from None

    resolved_ips = []
    for family, _, _, _, sockaddr in infos:
        if family in (socket.AF_INET, socket.AF_INET6):
            resolved_ip = sockaddr[0]
            _validate_target(resolved_ip)
            if resolved_ip not in resolved_ips:
                resolved_ips.append(resolved_ip)

    if resolved_ips:
        return resolved_ips[0], resolved_ips

    raise GeoIPError(f"Could not resolve hostname to an IP address: {target}")


async def _reverse_dns(ip: str) -> str | None:
    loop = asyncio.get_running_loop()
    try:
        hostname, _, _ = await loop.run_in_executor(None, socket.gethostbyaddr, ip)
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return None


_CDN_PATTERNS: dict[str, tuple[str, ...]] = {
    "Cloudflare": ("cloudflare", "as13335"),
    "Akamai": ("akamai", "as20940", "as16625"),
    "Fastly": ("fastly", "as54113"),
    "Amazon CloudFront": ("cloudfront", "amazon", "aws", "as16509"),
    "Google Cloud CDN": ("google", "google cloud", "as15169"),
    "Azure Front Door": ("azure", "microsoft", "as8075"),
    "Imperva": ("imperva", "incapsula", "as19551"),
    "Sucuri": ("sucuri", "as30148"),
    "Bunny CDN": ("bunny", "bunnycdn", "as200325"),
    "StackPath": ("stackpath", "highwinds", "as20446"),
    "Cloudflare Magic Transit": ("cloudflare", "as13335"),
}


def _detect_cdn(result: GeoIPResult) -> tuple[bool, str | None]:
    haystack = " ".join(
        str(value).lower()
        for value in (result.isp, result.org, result.asn, result.asn_domain, result.asn_type, result.reverse_dns)
        if value
    )
    for provider, needles in _CDN_PATTERNS.items():
        if any(needle in haystack for needle in needles):
            return True, provider
    return False, None


def _extract_rdap_abuse(entities: list[dict] | None) -> tuple[str | None, str | None]:
    if not entities:
        return None, None

    email = None
    phone = None
    for entity in entities:
        roles = {str(role).lower() for role in entity.get("roles", [])}
        if "abuse" not in roles:
            nested_email, nested_phone = _extract_rdap_abuse(entity.get("entities"))
            email = email or nested_email
            phone = phone or nested_phone
            continue

        for vcard_item in entity.get("vcardArray", [None, []])[1]:
            if len(vcard_item) < 4:
                continue
            if vcard_item[0] == "email":
                email = email or vcard_item[3]
            if vcard_item[0] == "tel":
                phone = phone or vcard_item[3]
        nested_email, nested_phone = _extract_rdap_abuse(entity.get("entities"))
        email = email or nested_email
        phone = phone or nested_phone
    return email, phone


async def _fetch_rdap(ip: str) -> dict:
    url = f"https://rdap.org/ip/{ip}"
    async with httpx.AsyncClient(timeout=settings.GEOIP_TIMEOUT) as client:
        resp = await client.get(url)

    if resp.status_code == 404:
        return {}
    resp.raise_for_status()
    return resp.json()


async def _apply_rdap(result: GeoIPResult) -> None:
    if not result.ip:
        return

    try:
        rdap = await _fetch_rdap(result.ip)
    except httpx.HTTPError:
        return

    notices = rdap.get("notices") or []
    registry = None
    for notice in notices:
        title = str(notice.get("title", "")).lower()
        if "arin" in title:
            registry = "ARIN"
        elif "ripe" in title:
            registry = "RIPE"
        elif "apnic" in title:
            registry = "APNIC"
        elif "lacnic" in title:
            registry = "LACNIC"
        elif "afrinic" in title:
            registry = "AFRINIC"

    abuse_email, abuse_phone = _extract_rdap_abuse(rdap.get("entities"))
    result.rdap_name = rdap.get("name")
    result.rdap_handle = rdap.get("handle")
    result.rdap_registry = registry
    cidr = rdap.get("cidr0_cidrs", [{}])[0] if rdap.get("cidr0_cidrs") else {}
    prefix = cidr.get("v4prefix") or cidr.get("v6prefix")
    length = cidr.get("length")
    result.rdap_cidr = f"{prefix}/{length}" if prefix and length is not None else prefix
    result.rdap_country = rdap.get("country")
    result.rdap_start_address = rdap.get("startAddress")
    result.rdap_end_address = rdap.get("endAddress")
    result.rdap_abuse_email = abuse_email
    result.rdap_abuse_phone = abuse_phone
    result.abuse_contact = abuse_email or abuse_phone or result.abuse_contact
    result.rdap_events = [
        {"action": event.get("eventAction"), "date": event.get("eventDate")}
        for event in rdap.get("events", [])
        if event.get("eventAction") or event.get("eventDate")
    ]


def _finalize_intelligence(result: GeoIPResult) -> None:
    is_cdn, cdn_provider = _detect_cdn(result)
    result.is_cdn = is_cdn
    result.cdn_provider = cdn_provider
    if is_cdn:
        result.is_proxy = True if result.is_proxy is None else result.is_proxy
        result.is_hosting = True if result.is_hosting is None else result.is_hosting
        result.infrastructure_note = (
            f"{result.target} resolves to {cdn_provider} edge/proxy infrastructure. "
            "GeoIP location describes the public edge, not necessarily the origin server."
        )
        result.confidence = "high"
    elif result.asn or result.org:
        result.infrastructure_note = "GeoIP identifies the public network endpoint. Origin location may differ for proxied or load-balanced services."
        result.confidence = "medium"


def _result_summary(result: GeoIPResult) -> str:
    bits = [result.target]
    if result.ip:
        bits.append(f"resolves to {result.ip}")
    if result.cdn_provider:
        bits.append(f"on {result.cdn_provider} edge infrastructure")
    elif result.org or result.isp:
        bits.append(f"on {result.org or result.isp}")
    if result.country:
        bits.append(f"in {result.country}")
    return " ".join(bits) + "."


def _public_result(result: GeoIPResult) -> dict:
    data = dict(result.__dict__)
    data["summary"] = _result_summary(result)
    data.pop("raw", None)
    data.pop("ip_results", None)
    return data


def _clone_result(result: GeoIPResult, *, cached: bool) -> GeoIPResult:
    return GeoIPResult(
        target=result.target,
        ip=result.ip,
        resolved_ips=list(result.resolved_ips),
        reverse_dns=result.reverse_dns,
        country=result.country,
        country_code=result.country_code,
        continent=result.continent,
        continent_code=result.continent_code,
        region=result.region,
        city=result.city,
        postal=result.postal,
        lat=result.lat,
        lon=result.lon,
        accuracy_radius=result.accuracy_radius,
        map_url=result.map_url,
        isp=result.isp,
        org=result.org,
        asn=result.asn,
        asn_route=result.asn_route,
        asn_domain=result.asn_domain,
        asn_type=result.asn_type,
        timezone=result.timezone,
        local_time=result.local_time,
        timezone_utc=result.timezone_utc,
        currency=result.currency,
        calling_code=result.calling_code,
        flag_emoji=result.flag_emoji,
        flag_image=result.flag_image,
        is_proxy=result.is_proxy,
        is_vpn=result.is_vpn,
        is_tor=result.is_tor,
        is_hosting=result.is_hosting,
        is_mobile=result.is_mobile,
        threat_score=result.threat_score,
        abuse_contact=result.abuse_contact,
        cdn_provider=result.cdn_provider,
        is_cdn=result.is_cdn,
        infrastructure_note=result.infrastructure_note,
        confidence=result.confidence,
        location_accuracy=result.location_accuracy,
        rdap_name=result.rdap_name,
        rdap_handle=result.rdap_handle,
        rdap_registry=result.rdap_registry,
        rdap_cidr=result.rdap_cidr,
        rdap_country=result.rdap_country,
        rdap_start_address=result.rdap_start_address,
        rdap_end_address=result.rdap_end_address,
        rdap_abuse_email=result.rdap_abuse_email,
        rdap_abuse_phone=result.rdap_abuse_phone,
        rdap_events=list(result.rdap_events),
        ip_results=[dict(item) for item in result.ip_results],
        raw=dict(result.raw) if result.raw else None,
        provider=result.provider,
        cached=cached,
        error=result.error,
    )


def _cache_key(provider_name: str, target: str) -> str:
    return f"{provider_name}:{target.lower()}"


def register_geoip_provider(provider: GeoIPProvider) -> None:
    _PROVIDERS[provider.name] = provider


def clear_geoip_cache() -> None:
    _CACHE.clear()


async def geoip_lookup(target: str, provider_name: str | None = None) -> GeoIPResult:
    provider_key = provider_name or settings.GEOIP_PROVIDER
    provider = _PROVIDERS.get(provider_key)
    if provider is None:
        return _empty_result(target, f"Unsupported GeoIP provider: {provider_key}", provider_key)

    try:
        normalized = _validate_target(target)
        lookup_target, resolved_ips = await _resolve_target(normalized)
        key = _cache_key(provider.name, lookup_target)
        now = time.time()
        cached = _CACHE.get(key)
        if cached and cached[0] > now:
            cached_result = _clone_result(cached[1], cached=True)
            cached_result.target = normalized
            cached_result.resolved_ips = resolved_ips
            return cached_result

        result = await provider.lookup(lookup_target)
        result.target = normalized
        result.resolved_ips = resolved_ips
        result.reverse_dns = await _reverse_dns(lookup_target)
        await _apply_rdap(result)
        _finalize_intelligence(result)

        ip_results = [_public_result(result)]
        for extra_ip in resolved_ips[1:]:
            extra_key = _cache_key(provider.name, extra_ip)
            extra_cached = _CACHE.get(extra_key)
            if extra_cached and extra_cached[0] > now:
                extra = _clone_result(extra_cached[1], cached=True)
            else:
                extra = await provider.lookup(extra_ip)
                extra.resolved_ips = [extra_ip]
                extra.reverse_dns = await _reverse_dns(extra_ip)
                await _apply_rdap(extra)
                _finalize_intelligence(extra)
                _CACHE[extra_key] = (now + settings.GEOIP_CACHE_TTL_SECONDS, _clone_result(extra, cached=False))
            extra.target = extra_ip
            ip_results.append(_public_result(extra))

        result.ip_results = ip_results
        _CACHE[key] = (now + settings.GEOIP_CACHE_TTL_SECONDS, _clone_result(result, cached=False))
        return result
    except httpx.TimeoutException:
        return _empty_result(target, "GeoIP provider timed out", provider.name)
    except httpx.HTTPError as exc:
        return _empty_result(target, f"GeoIP provider request failed: {exc}", provider.name)
    except GeoIPError as exc:
        return _empty_result(target, str(exc), provider.name)
    except Exception as exc:
        return _empty_result(target, f"Unexpected GeoIP error: {exc}", provider.name)
