from __future__ import annotations

import asyncio
import collections
import socket
import time
from dataclasses import dataclass
from ipaddress import ip_address
from typing import Optional, Protocol

import httpx

from cybersec.config import settings


class _LRUCache:
    """
    Simple LRU cache with TTL support.
    
    NOTE: This cache is process-local. If the app runs as multiple worker processes
    or multiple instances behind a load balancer, each will have its own independent
    cache. A cache hit in one process is invisible to another, meaning actual upstream
    request volume is undercounted by this module's rate limiter logic.
    
    For multi-process deployments, consider replacing this with Redis.
    """
    def __init__(self, max_size: int):
        self._cache: collections.OrderedDict[str, tuple[float, GeoIPResult]] = collections.OrderedDict()
        self._max_size = max_size
        self._lock = asyncio.Lock()
    
    async def get(self, key: str, now: float) -> Optional[GeoIPResult]:
        """Get entry if it exists and hasn't expired. Moves to end on hit (LRU)."""
        async with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                return None
            expiry, result = entry
            if expiry <= now:
                # Expired, remove it
                del self._cache[key]
                return None
            # Move to end (most recently used)
            self._cache.move_to_end(key)
            return result
    
    async def set(self, key: str, expiry: float, result: GeoIPResult) -> None:
        """Set entry, evicting oldest if over max size."""
        async with self._lock:
            if key in self._cache:
                del self._cache[key]
            self._cache[key] = (expiry, result)
            self._cache.move_to_end(key)
            # Evict oldest if over max size
            while len(self._cache) > self._max_size:
                self._cache.popitem(last=False)
    
    async def clear(self) -> None:
        """Clear all entries."""
        async with self._lock:
            self._cache.clear()
    
    async def sweep_expired(self, now: float) -> int:
        """Remove all expired entries. Returns count of removed entries."""
        async with self._lock:
            expired_keys = [k for k, (expiry, _) in self._cache.items() if expiry <= now]
            for key in expired_keys:
                del self._cache[key]
            return len(expired_keys)
    
    def size(self) -> int:
        """Return current cache size."""
        return len(self._cache)


class _RateLimiter:
    def __init__(self, max_per_minute: int):
        self.max_per_minute = max_per_minute
        self._timestamps: collections.deque[float] = collections.deque()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.time()
            while self._timestamps and now - self._timestamps[0] > 60:
                self._timestamps.popleft()
            if len(self._timestamps) >= self.max_per_minute:
                wait = 60 - (now - self._timestamps[0])
                await asyncio.sleep(max(wait, 0))
            self._timestamps.append(time.time())


_geoip_rate_limiter = _RateLimiter(settings.GEOIP_RATE_LIMIT_PER_MINUTE)
# Known limitation: this is an in-memory, per-process rate limiter. If
# the app runs multiple worker processes/instances, each process will get its
# own budget, which may collectively exceed the ipwho.is rate limit. A
# production-grade fix would use a shared store (like Redis) for cross-process
# coordination, which is out of scope for this fix.


@dataclass
class RDAPData:
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
    abuse_contact: str | None


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
        await _geoip_rate_limiter.acquire()
        url = f"https://ipwho.is/{target}"
        client = _get_http_client()
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
        currency = data.get("currency") or {}
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
            currency=currency.get("code") if isinstance(currency, dict) else currency,
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


class IPApiProvider:
    name = "ipapi"

    async def lookup(self, target: str) -> GeoIPResult:
        await _geoip_rate_limiter.acquire()
        url = f"http://ip-api.com/json/{target}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,mobile,proxy,hosting"
        client = _get_http_client()
        resp = await client.get(url)

        if resp.status_code == 429:
            raise GeoIPError("GeoIP provider rate limit reached. Try again later.")
        resp.raise_for_status()
        data = resp.json()

        if data.get("status") == "fail":
            raise GeoIPError(data.get("message", "GeoIP lookup failed"))

        lat = data.get("lat")
        lon = data.get("lon")
        asn = data.get("as")

        return GeoIPResult(
            target=target,
            ip=data.get("query"),
            resolved_ips=[],
            reverse_dns=None,
            country=data.get("country"),
            country_code=data.get("countryCode"),
            continent=None,  # Not available from ip-api.com free tier
            continent_code=None,  # Not available
            region=data.get("regionName"),
            city=data.get("city"),
            postal=data.get("zip"),
            lat=lat,
            lon=lon,
            accuracy_radius=None,  # Not available
            map_url=f"https://www.google.com/maps/search/?api=1&query={lat},{lon}" if lat is not None and lon is not None else None,
            isp=data.get("isp"),
            org=data.get("org"),
            asn=asn,
            asn_route=None,  # Not available
            asn_domain=None,  # Not available
            asn_type=None,  # Not available
            timezone=data.get("timezone"),
            local_time=None,  # Not available
            timezone_utc=None,  # Not available
            currency=None,  # Not available
            calling_code=None,  # Not available
            flag_emoji=None,  # Not available
            flag_image=None,  # Not available
            is_proxy=data.get("proxy"),
            is_vpn=None,  # Not available
            is_tor=None,  # Not available
            is_hosting=data.get("hosting"),
            is_mobile=data.get("mobile"),
            threat_score=None,  # Not available
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


_PROVIDERS: dict[str, GeoIPProvider] = {}
_PROVIDER_FALLBACK_ORDER: list[str] = ["ipwhois", "ipapi"]
_CACHE: _LRUCache = _LRUCache(max_size=settings.GEOIP_CACHE_MAX_ENTRIES)
_GEOIP_SEMAPHORE: asyncio.Semaphore = asyncio.Semaphore(settings.GEOIP_MAX_CONCURRENT_LOOKUPS)
_http_client: Optional[httpx.AsyncClient] = None
_cache_sweep_task: Optional[asyncio.Task] = None


async def _retry_transient(func, max_retries=1, delay=0.3):
    """
    Retry function on transient errors: timeouts, 502, 503 HTTP errors.
    """
    retries = 0
    last_exception = None
    while retries <= max_retries:
        try:
            return await func()
        except (httpx.TimeoutException, httpx.HTTPStatusError) as e:
            should_retry = False
            if isinstance(e, httpx.TimeoutException):
                should_retry = True
            elif isinstance(e, httpx.HTTPStatusError):
                if e.response.status_code in (502, 503):
                    should_retry = True
            if should_retry and retries < max_retries:
                last_exception = e
                retries += 1
                await asyncio.sleep(delay)
                continue
            raise
        except Exception:
            raise


async def _try_providers(lookup_target: str, provider_name: str | None = None):
    """
    Try providers in fallback order, return result and note if fallback happened.
    """
    if provider_name is not None:
        # If specific provider is requested, only use that one, no fallback
        provider = _PROVIDERS.get(provider_name)
        if provider is None:
            raise GeoIPError(f"Unsupported GeoIP provider: {provider_name}")
        try:
            result = await _retry_transient(lambda: provider.lookup(lookup_target))
            return result, None, None
        except Exception as e:
            raise

    # No specific provider, try fallback order
    last_error = None
    errors = []
    for i, name in enumerate(_PROVIDER_FALLBACK_ORDER):
        provider = _PROVIDERS.get(name)
        if not provider:
            continue
        try:
            result = await _retry_transient(lambda: provider.lookup(lookup_target))
            fallback_note = None
            if i > 0:
                fallback_note = f"Fell back from {_PROVIDER_FALLBACK_ORDER[:i]} to {name}"
            return result, fallback_note, None
        except Exception as e:
            # Check if it's a client error (like invalid IP) that shouldn't trigger fallback
            client_error = False
            if isinstance(e, httpx.HTTPStatusError):
                if 400 <= e.response.status_code < 500 and e.response.status_code != 429:
                    client_error = True
            if client_error:
                # Don't fall back for client errors like invalid inputs
                raise
            last_error = e
            errors.append(f"{name}: {str(e)}")

    # All providers failed
    combined_error = "All providers failed: " + "; ".join(errors) if errors else "GeoIP lookup failed"
    raise GeoIPError(combined_error)


def _get_http_client() -> httpx.AsyncClient:
    global _http_client
    if _http_client is None:
        _http_client = httpx.AsyncClient(
            timeout=settings.GEOIP_TIMEOUT,
            limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
        )
    return _http_client


async def close_http_client() -> None:
    global _http_client
    if _http_client is not None:
        try:
            await _http_client.aclose()
        except Exception:
            pass
        _http_client = None


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
    client = _get_http_client()
    resp = await client.get(url)

    if resp.status_code == 404:
        return {}
    resp.raise_for_status()
    return resp.json()


async def _apply_rdap(ip: str | None) -> RDAPData | None:
    if not ip:
        return None

    try:
        rdap = await _fetch_rdap(ip)
    except httpx.HTTPError:
        return None

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
    cidr = rdap.get("cidr0_cidrs", [{}])[0] if rdap.get("cidr0_cidrs") else {}
    prefix = cidr.get("v4prefix") or cidr.get("v6prefix")
    length = cidr.get("length")
    return RDAPData(
        rdap_name=rdap.get("name"),
        rdap_handle=rdap.get("handle"),
        rdap_registry=registry,
        rdap_cidr=f"{prefix}/{length}" if prefix and length is not None else prefix,
        rdap_country=rdap.get("country"),
        rdap_start_address=rdap.get("startAddress"),
        rdap_end_address=rdap.get("endAddress"),
        rdap_abuse_email=abuse_email,
        rdap_abuse_phone=abuse_phone,
        rdap_events=[
            {"action": event.get("eventAction"), "date": event.get("eventDate")}
            for event in rdap.get("events", [])
            if event.get("eventAction") or event.get("eventDate")
        ],
        abuse_contact=abuse_email or abuse_phone,
    )


def _apply_rdap_data(result: GeoIPResult, rdap_data: RDAPData | None) -> None:
    if rdap_data is None:
        return
    result.rdap_name = rdap_data.rdap_name
    result.rdap_handle = rdap_data.rdap_handle
    result.rdap_registry = rdap_data.rdap_registry
    result.rdap_cidr = rdap_data.rdap_cidr
    result.rdap_country = rdap_data.rdap_country
    result.rdap_start_address = rdap_data.rdap_start_address
    result.rdap_end_address = rdap_data.rdap_end_address
    result.rdap_abuse_email = rdap_data.rdap_abuse_email
    result.rdap_abuse_phone = rdap_data.rdap_abuse_phone
    result.rdap_events = rdap_data.rdap_events
    result.abuse_contact = rdap_data.abuse_contact or result.abuse_contact


async def _lookup_one_ip(ip: str, now: float, provider_name: str | None = None) -> GeoIPResult:
    # For cache key, use first provider if no specific provider is given
    cache_provider = provider_name or _PROVIDER_FALLBACK_ORDER[0]
    extra_key = _cache_key(cache_provider, ip)
    extra_cached = await _CACHE.get(extra_key, now)
    if extra_cached:
        return _clone_result(extra_cached, cached=True)
    
    async with _GEOIP_SEMAPHORE:
        try:
            result, fallback_note, _ = await _try_providers(ip, provider_name)
        except GeoIPError as e:
            return _empty_result(ip, str(e), cache_provider)
                
        result.resolved_ips = [ip]
        extra_reverse_dns, extra_rdap_data = await asyncio.gather(
            _reverse_dns(ip),
            _apply_rdap(ip)
        )
        result.reverse_dns = extra_reverse_dns
        _apply_rdap_data(result, extra_rdap_data)
    
    _finalize_intelligence(result)
    
    # Append fallback note after finalize_intelligence so it's not overwritten
    if fallback_note:
        if result.infrastructure_note:
            result.infrastructure_note = f"{result.infrastructure_note} | {fallback_note}"
        else:
            result.infrastructure_note = fallback_note
    
    await _CACHE.set(extra_key, now + settings.GEOIP_CACHE_TTL_SECONDS, _clone_result(result, cached=False))
    return result


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


async def clear_geoip_cache() -> None:
    """Clear all entries from the cache."""
    await _CACHE.clear()


async def geoip_lookup(target: str, provider_name: str | None = None) -> GeoIPResult:
    try:
        normalized = _validate_target(target)
        lookup_target, resolved_ips = await _resolve_target(normalized)
        # For cache key, use first provider if no specific provider is given, since fallback could change provider
        cache_provider = provider_name or _PROVIDER_FALLBACK_ORDER[0]
        key = _cache_key(cache_provider, lookup_target)
        now = time.time()
        cached = await _CACHE.get(key, now)
        if cached:
            cached_result = _clone_result(cached, cached=True)
            cached_result.target = normalized
            cached_result.resolved_ips = resolved_ips
            return cached_result

        # Try providers with fallback
        try:
            result, fallback_note, _ = await _try_providers(lookup_target, provider_name)
        except GeoIPError as e:
            return _empty_result(normalized, str(e), cache_provider)
        
        result.target = normalized
        result.resolved_ips = resolved_ips
                
        reverse_dns, rdap_data = await asyncio.gather(
            _reverse_dns(lookup_target),
            _apply_rdap(result.ip)
        )
        result.reverse_dns = reverse_dns
        _apply_rdap_data(result, rdap_data)
        _finalize_intelligence(result)
        
        # Append fallback note after finalize_intelligence so it's not overwritten
        if fallback_note:
            if result.infrastructure_note:
                result.infrastructure_note = f"{result.infrastructure_note} | {fallback_note}"
            else:
                result.infrastructure_note = fallback_note

        ip_results = [_public_result(result)]
        extra_results = await asyncio.gather(
            *[_lookup_one_ip(ip, now, provider_name) for ip in resolved_ips[1:]],
            return_exceptions=True,
        )
        for extra_ip, extra_result in zip(resolved_ips[1:], extra_results):
            if isinstance(extra_result, Exception):
                # Create an empty result for failed IP
                extra = _empty_result(extra_ip, f"Failed to lookup {extra_ip}: {str(extra_result)}", cache_provider)
            else:
                extra = extra_result
                extra.target = extra_ip
            ip_results.append(_public_result(extra))

        result.ip_results = ip_results
        await _CACHE.set(key, now + settings.GEOIP_CACHE_TTL_SECONDS, _clone_result(result, cached=False))
        return result
    except httpx.TimeoutException as e:
        return _empty_result(target, "GeoIP provider timed out", provider_name or _PROVIDER_FALLBACK_ORDER[0])
    except httpx.HTTPError as exc:
        return _empty_result(target, f"GeoIP provider request failed: {exc}", provider_name or _PROVIDER_FALLBACK_ORDER[0])
    except GeoIPError as exc:
        return _empty_result(target, str(exc), provider_name or _PROVIDER_FALLBACK_ORDER[0])
    except Exception as exc:
        return _empty_result(target, f"Unexpected GeoIP error: {exc}", provider_name or _PROVIDER_FALLBACK_ORDER[0])


async def _cache_sweep_loop():
    """Background task that periodically sweeps expired cache entries."""
    global _cache_sweep_task
    try:
        while True:
            await asyncio.sleep(settings.GEOIP_CACHE_SWEEP_INTERVAL_SECONDS)
            now = time.time()
            removed = await _CACHE.sweep_expired(now)
            if removed > 0:
                # Log sweep results (could use proper logger in production)
                pass
    except asyncio.CancelledError:
        # Task was cancelled during shutdown
        raise


async def start_geoip_cache_sweep():
    """Start the background cache sweep task."""
    global _cache_sweep_task
    if _cache_sweep_task is None or _cache_sweep_task.done():
        _cache_sweep_task = asyncio.create_task(_cache_sweep_loop())


async def stop_geoip_cache_sweep():
    """Stop the background cache sweep task."""
    global _cache_sweep_task
    if _cache_sweep_task and not _cache_sweep_task.done():
        _cache_sweep_task.cancel()
        try:
            await _cache_sweep_task
        except asyncio.CancelledError:
            pass
        _cache_sweep_task = None
