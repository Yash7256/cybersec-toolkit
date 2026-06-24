import asyncio

import httpx
import pytest
import respx
from unittest.mock import AsyncMock

from cybersec.core.tools import geoip
from cybersec.core.tools.geoip import GeoIPError, GeoIPResult, IPWhoIsProvider, _validate_target, _detect_cdn, _extract_rdap_abuse, _result_summary


def make_result(**overrides) -> GeoIPResult:
    """Return a minimal valid GeoIPResult with all fields set to safe defaults,
    overriding only what the test needs."""
    defaults = dict(
        target="8.8.8.8", ip="8.8.8.8", resolved_ips=[], reverse_dns=None,
        country=None, country_code=None, continent=None, continent_code=None,
        region=None, city=None, postal=None, lat=None, lon=None,
        accuracy_radius=None, map_url=None, isp=None, org=None, asn=None,
        asn_route=None, asn_domain=None, asn_type=None, timezone=None,
        local_time=None, timezone_utc=None, currency=None, calling_code=None,
        flag_emoji=None, flag_image=None, is_proxy=None, is_vpn=None,
        is_tor=None, is_hosting=None, is_mobile=None, threat_score=None,
        abuse_contact=None, cdn_provider=None, is_cdn=False,
        infrastructure_note=None, confidence="medium", location_accuracy=None,
        rdap_name=None, rdap_handle=None, rdap_registry=None, rdap_cidr=None,
        rdap_country=None, rdap_start_address=None, rdap_end_address=None,
        rdap_abuse_email=None, rdap_abuse_phone=None, rdap_events=[],
        ip_results=[], raw=None, provider="fake", cached=False, error=None,
    )
    defaults.update(overrides)
    return GeoIPResult(**defaults)


class FakeProvider:
    name = "fake"

    def __init__(self) -> None:
        self.calls = 0

    async def lookup(self, target: str) -> GeoIPResult:
        self.calls += 1
        return GeoIPResult(
            target=target,
            ip="8.8.8.8",
            resolved_ips=[],
            reverse_dns=None,
            country="United States",
            country_code="US",
            continent="North America",
            continent_code="NA",
            region="CA",
            city="Mountain View",
            postal="94043",
            lat=37.4056,
            lon=-122.0775,
            accuracy_radius=None,
            map_url="https://www.google.com/maps/search/?api=1&query=37.4056,-122.0775",
            isp="Google LLC",
            org="Google Public DNS",
            asn="AS15169 Google LLC",
            asn_route=None,
            asn_domain="google.com",
            asn_type="business",
            timezone="America/Los_Angeles",
            local_time=None,
            timezone_utc="-08:00",
            currency="USD",
            calling_code="1",
            flag_emoji="🇺🇸",
            flag_image=None,
            is_proxy=False,
            is_vpn=False,
            is_tor=False,
            is_hosting=True,
            is_mobile=False,
            threat_score=None,
            abuse_contact=None,
            cdn_provider=None,
            is_cdn=False,
            infrastructure_note=None,
            confidence="medium",
            location_accuracy="city",
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
            provider=self.name,
            cached=False,
            error=None,
        )


class CDNFakeProvider:
    name = "cdn_fake"

    def __init__(self) -> None:
        self.calls = 0

    async def lookup(self, target: str) -> GeoIPResult:
        self.calls += 1
        return GeoIPResult(
            target=target,
            ip="1.1.1.1",
            resolved_ips=[],
            reverse_dns=None,
            country="United States",
            country_code="US",
            continent="North America",
            continent_code="NA",
            region=None,
            city=None,
            postal=None,
            lat=None,
            lon=None,
            accuracy_radius=None,
            map_url=None,
            isp="Cloudflare, Inc.",
            org="Cloudflare, Inc.",
            asn="AS13335",
            asn_route=None,
            asn_domain="cloudflare.com",
            asn_type="business",
            timezone=None,
            local_time=None,
            timezone_utc=None,
            currency=None,
            calling_code=None,
            flag_emoji=None,
            flag_image=None,
            is_proxy=True,
            is_vpn=None,
            is_tor=None,
            is_hosting=None,
            is_mobile=None,
            threat_score=None,
            abuse_contact=None,
            cdn_provider=None,
            is_cdn=False,
            infrastructure_note=None,
            confidence="medium",
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
            provider=self.name,
            cached=False,
            error=None,
        )


class NullFieldProvider:
    name = "null_fake"

    def __init__(self) -> None:
        self.calls = 0

    async def lookup(self, target: str) -> GeoIPResult:
        self.calls += 1
        return GeoIPResult(
            target=target,
            ip="8.8.8.8",
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
            confidence="medium",
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
            provider=self.name,
            cached=False,
            error=None,
        )


@pytest.fixture(autouse=True)
def isolate_geoip(monkeypatch):
    fake = FakeProvider()
    cdn = CDNFakeProvider()
    null = NullFieldProvider()

    geoip.register_geoip_provider(fake)
    geoip.register_geoip_provider(cdn)
    geoip.register_geoip_provider(null)

    monkeypatch.setattr(geoip, "_fetch_rdap", AsyncMock(return_value={}))
    monkeypatch.setattr(geoip, "_reverse_dns", AsyncMock(return_value=None))

    geoip._http_client = None
    asyncio.run(geoip.clear_geoip_cache())
    yield fake
    geoip._http_client = None
    asyncio.run(geoip.clear_geoip_cache())


# ── TIER 1: UNIT ──


@pytest.mark.unit
def test_validate_empty_string():
    with pytest.raises(GeoIPError, match="Target is required"):
        _validate_target("")


@pytest.mark.unit
def test_validate_whitespace_only():
    with pytest.raises(GeoIPError, match="Target is required"):
        _validate_target("   ")


@pytest.mark.unit
def test_validate_too_long():
    with pytest.raises(GeoIPError, match="Target is too long"):
        _validate_target("a" * 254)


@pytest.mark.unit
def test_validate_exactly_253_chars():
    result = _validate_target("a" * 253)
    assert result == "a" * 253


@pytest.mark.unit
def test_validate_contains_space():
    with pytest.raises(GeoIPError, match="Target must be a single IP address or hostname"):
        _validate_target("8.8.8.8 9.9.9.9")


@pytest.mark.unit
def test_validate_private_10_block():
    with pytest.raises(GeoIPError, match="not sent to external GeoIP providers"):
        _validate_target("10.0.0.1")


@pytest.mark.unit
def test_validate_private_192_168():
    with pytest.raises(GeoIPError, match="not sent to external GeoIP providers"):
        _validate_target("192.168.1.1")


@pytest.mark.unit
def test_validate_private_172_16():
    with pytest.raises(GeoIPError, match="not sent to external GeoIP providers"):
        _validate_target("172.16.0.1")


@pytest.mark.unit
def test_validate_loopback_ipv4():
    with pytest.raises(GeoIPError, match="not sent to external GeoIP providers"):
        _validate_target("127.0.0.1")


@pytest.mark.unit
def test_validate_loopback_ipv6():
    with pytest.raises(GeoIPError, match="not sent to external GeoIP providers"):
        _validate_target("::1")


@pytest.mark.unit
def test_validate_link_local_169_254():
    with pytest.raises(GeoIPError, match="not sent to external GeoIP providers"):
        _validate_target("169.254.169.254")


@pytest.mark.unit
def test_validate_multicast():
    with pytest.raises(GeoIPError, match="not sent to external GeoIP providers"):
        _validate_target("224.0.0.1")


@pytest.mark.unit
def test_validate_unspecified():
    with pytest.raises(GeoIPError, match="not sent to external GeoIP providers"):
        _validate_target("0.0.0.0")


@pytest.mark.unit
def test_validate_valid_public_ipv4():
    result = _validate_target("8.8.8.8")
    assert result == "8.8.8.8"


@pytest.mark.unit
def test_validate_valid_global_ipv6():
    result = _validate_target("2606:4700::")
    assert result == "2606:4700::"


@pytest.mark.unit
def test_validate_valid_hostname():
    result = _validate_target("example.com")
    assert result == "example.com"


@pytest.mark.unit
def test_validate_strips_leading_trailing_whitespace():
    result = _validate_target("  8.8.8.8  ")
    assert result == "8.8.8.8"


@pytest.mark.unit
def test_detect_cdn_cloudflare_by_org():
    result = make_result(org="Cloudflare, Inc.")
    detected, provider = _detect_cdn(result)
    assert detected is True
    assert provider == "Cloudflare"


@pytest.mark.unit
def test_detect_cdn_cloudflare_by_asn():
    result = make_result(asn="AS13335")
    detected, provider = _detect_cdn(result)
    assert detected is True
    assert provider == "Cloudflare"


@pytest.mark.unit
def test_detect_cdn_akamai_by_isp():
    result = make_result(isp="Akamai Technologies")
    detected, provider = _detect_cdn(result)
    assert detected is True
    assert provider == "Akamai"


@pytest.mark.unit
def test_detect_cdn_fastly_by_org():
    result = make_result(org="Fastly CDN")
    detected, provider = _detect_cdn(result)
    assert detected is True
    assert provider == "Fastly"


@pytest.mark.unit
def test_detect_cdn_cloudfront_by_org():
    result = make_result(org="Amazon CloudFront")
    detected, provider = _detect_cdn(result)
    assert detected is True
    assert provider == "Amazon CloudFront"


@pytest.mark.unit
def test_detect_cdn_google_by_asn():
    result = make_result(asn="AS15169")
    detected, provider = _detect_cdn(result)
    assert detected is True
    assert provider == "Google Cloud CDN"


@pytest.mark.unit
def test_detect_cdn_azure_by_org():
    result = make_result(org="Microsoft Azure")
    detected, provider = _detect_cdn(result)
    assert detected is True
    assert provider == "Azure Front Door"


@pytest.mark.unit
def test_detect_cdn_sucuri_by_isp():
    result = make_result(isp="Sucuri Security")
    detected, provider = _detect_cdn(result)
    assert detected is True
    assert provider == "Sucuri"


@pytest.mark.unit
def test_detect_cdn_no_match():
    result = make_result(org="Random ISP Ltd", isp="Some Telecom", asn="AS99999")
    detected, provider = _detect_cdn(result)
    assert detected is False
    assert provider is None


@pytest.mark.unit
def test_detect_cdn_case_insensitive():
    result = make_result(org="CLOUDFLARE, INC.")
    detected, provider = _detect_cdn(result)
    assert detected is True
    assert provider == "Cloudflare"


@pytest.mark.unit
def test_detect_cdn_match_via_reverse_dns():
    result = make_result(reverse_dns="edge.cloudflare.net")
    detected, provider = _detect_cdn(result)
    assert detected is True
    assert provider == "Cloudflare"


@pytest.mark.unit
def test_rdap_abuse_direct_entity_email_only():
    entities = [{"roles": ["abuse"], "vcardArray": ["vcard", [["email", {}, "text", "a@b.com"]]]}]
    email, phone = _extract_rdap_abuse(entities)
    assert email == "a@b.com"
    assert phone is None


@pytest.mark.unit
def test_rdap_abuse_direct_entity_phone_only():
    entities = [{"roles": ["abuse"], "vcardArray": ["vcard", [["tel", {}, "text", "+1-800-000-0000"]]]}]
    email, phone = _extract_rdap_abuse(entities)
    assert email is None
    assert phone == "+1-800-000-0000"


@pytest.mark.unit
def test_rdap_abuse_email_and_phone():
    entities = [{"roles": ["abuse"], "vcardArray": ["vcard", [["email", {}, "text", "a@b.com"], ["tel", {}, "text", "+1-800-000-0000"]]]}]
    email, phone = _extract_rdap_abuse(entities)
    assert email == "a@b.com"
    assert phone == "+1-800-000-0000"


@pytest.mark.unit
def test_rdap_abuse_nested_one_level():
    entities = [
        {"roles": ["registrant"], "vcardArray": ["vcard", []]},
        {"roles": ["abuse"], "vcardArray": ["vcard", [["email", {}, "text", "nested@example.com"]]]}
    ]
    email, phone = _extract_rdap_abuse(entities)
    assert email == "nested@example.com"
    assert phone is None


@pytest.mark.unit
def test_rdap_abuse_non_abuse_role_ignored():
    entities = [{"roles": ["registrant"], "vcardArray": ["vcard", [["email", {}, "text", "a@b.com"]]]}]
    email, phone = _extract_rdap_abuse(entities)
    assert email is None
    assert phone is None


@pytest.mark.unit
def test_rdap_abuse_empty_list():
    email, phone = _extract_rdap_abuse([])
    assert email is None
    assert phone is None


@pytest.mark.unit
def test_rdap_abuse_none_input():
    email, phone = _extract_rdap_abuse(None)
    assert email is None
    assert phone is None


@pytest.mark.unit
def test_rdap_abuse_short_vcard_item_skipped():
    entities = [{"roles": ["abuse"], "vcardArray": ["vcard", [["short"]]]}]
    email, phone = _extract_rdap_abuse(entities)
    assert email is None
    assert phone is None


@pytest.mark.unit
def test_summary_cdn_provider_present():
    result = make_result(ip="1.1.1.1", cdn_provider="Cloudflare", country="United States")
    summary = _result_summary(result)
    assert "on Cloudflare edge infrastructure" in summary
    assert "in United States" in summary


@pytest.mark.unit
def test_summary_org_no_cdn():
    result = make_result(ip="8.8.8.8", org="Google LLC", country="United States")
    summary = _result_summary(result)
    assert "on Google LLC" in summary


@pytest.mark.unit
def test_summary_isp_fallback_when_no_org():
    result = make_result(ip="8.8.8.8", isp="Comcast", org=None)
    summary = _result_summary(result)
    assert "on Comcast" in summary


@pytest.mark.unit
def test_summary_country_only():
    result = make_result(ip="8.8.8.8", country="Japan", org=None, cdn_provider=None)
    summary = _result_summary(result)
    assert "in Japan" in summary


@pytest.mark.unit
def test_summary_bare_target_no_fields():
    result = make_result(target="mystery.host", ip=None, org=None, cdn_provider=None, country=None)
    summary = _result_summary(result)
    assert summary == "mystery.host."


# ── TIER 2: CACHE ──


@pytest.mark.unit
def test_cache_hit_avoids_second_provider_call():
    first = asyncio.run(geoip.geoip_lookup("8.8.8.8", provider_name="fake"))
    second = asyncio.run(geoip.geoip_lookup("8.8.8.8", provider_name="fake"))
    provider = geoip._PROVIDERS["fake"]
    assert provider.calls == 1
    assert first.cached is False
    assert second.cached is True


@pytest.mark.unit
def test_cache_miss_after_ttl_expiry(monkeypatch):
    import time as time_module
    from cybersec.config.settings import settings

    original_time = time_module.time
    call_count = [0]

    def mock_time():
        if call_count[0] == 0:
            call_count[0] += 1
            return 0
        else:
            return 0 + settings.GEOIP_CACHE_TTL_SECONDS + 1

    monkeypatch.setattr(time_module, "time", mock_time)

    first = asyncio.run(geoip.geoip_lookup("8.8.8.8", provider_name="fake"))
    second = asyncio.run(geoip.geoip_lookup("8.8.8.8", provider_name="fake"))
    provider = geoip._PROVIDERS["fake"]
    assert provider.calls == 2
    assert second.cached is False


@pytest.mark.unit
def test_cache_result_is_deep_copy_not_reference():
    r1 = asyncio.run(geoip.geoip_lookup("8.8.8.8", provider_name="fake"))
    r1.resolved_ips.append("MUTATED")
    r2 = asyncio.run(geoip.geoip_lookup("8.8.8.8", provider_name="fake"))
    assert "MUTATED" not in r2.resolved_ips


@pytest.mark.unit
def test_cache_key_lowercases_target(monkeypatch):
    async def fake_resolve(target):
        return ("8.8.8.8", ["8.8.8.8"])

    monkeypatch.setattr(geoip, "_resolve_target", fake_resolve)

    first = asyncio.run(geoip.geoip_lookup("8.8.8.8", provider_name="fake"))
    second = asyncio.run(geoip.geoip_lookup("8.8.8.8", provider_name="fake"))
    provider = geoip._PROVIDERS["fake"]
    assert provider.calls == 1


@pytest.mark.unit
def test_cache_separate_per_provider():
    fake_a = FakeProvider()
    fake_a.name = "fake_a"
    fake_b = FakeProvider()
    fake_b.name = "fake_b"

    geoip.register_geoip_provider(fake_a)
    geoip.register_geoip_provider(fake_b)

    first = asyncio.run(geoip.geoip_lookup("1.1.1.1", provider_name="fake_a"))
    second = asyncio.run(geoip.geoip_lookup("1.1.1.1", provider_name="fake_b"))
    assert fake_a.calls == 1
    assert fake_b.calls == 1


@pytest.mark.unit
def test_clear_cache_forces_fresh_fetch():
    first = asyncio.run(geoip.geoip_lookup("8.8.8.8", provider_name="fake"))
    asyncio.run(geoip.clear_geoip_cache())
    second = asyncio.run(geoip.geoip_lookup("8.8.8.8", provider_name="fake"))
    provider = geoip._PROVIDERS["fake"]
    assert provider.calls == 2
    assert second.cached is False


@pytest.mark.unit
def test_cache_target_set_correctly_on_cached_result(monkeypatch):
    async def fake_resolve_first(target):
        return ("8.8.8.8", ["8.8.8.8"])

    async def fake_resolve_second(target):
        return ("8.8.8.8", ["8.8.8.8"])

    monkeypatch.setattr(geoip, "_resolve_target", fake_resolve_first)

    first = asyncio.run(geoip.geoip_lookup("8.8.8.8", provider_name="fake"))

    monkeypatch.setattr(geoip, "_resolve_target", fake_resolve_second)

    second = asyncio.run(geoip.geoip_lookup("google-dns.test", provider_name="fake"))
    assert second.target == "google-dns.test"
    assert second.cached is True


# ── TIER 3: PROVIDER CONTRACT ──


@pytest.mark.unit
def test_ipwhois_happy_path_maps_all_fields(respx_mock):
    payload = {
        "success": True,
        "ip": "8.8.8.8",
        "country": "United States",
        "country_code": "US",
        "continent": "North America",
        "continent_code": "NA",
        "region": "California",
        "city": "Mountain View",
        "postal": "94043",
        "latitude": 37.4056,
        "longitude": -122.0775,
        "connection": {
            "asn": 15169,
            "org": "Google LLC",
            "isp": "Google LLC",
            "domain": "google.com",
            "type": "business",
            "route": "8.8.8.0/24"
        },
        "timezone": {
            "id": "America/Los_Angeles",
            "current_time": "2026-01-01T00:00:00",
            "utc": "-08:00"
        },
        "currency": {"code": "USD"},
        "calling_code": "1",
        "flag": {
            "emoji": "🇺🇸",
            "img": "https://cdn.ip-api.com/flags/us.svg"
        },
        "security": {
            "proxy": False,
            "vpn": False,
            "tor": False,
            "hosting": True,
            "mobile": False,
            "threat_score": 0
        }
    }
    respx_mock.get("https://ipwho.is/8.8.8.8").mock(return_value=httpx.Response(200, json=payload))

    provider = IPWhoIsProvider()
    result = asyncio.run(provider.lookup("8.8.8.8"))

    assert result.error is None
    assert result.country == "United States"
    assert result.country_code == "US"
    assert result.lat == 37.4056
    assert result.lon == -122.0775
    assert "37.4056,-122.0775" in result.map_url
    assert result.asn == "AS15169"
    assert result.asn_route == "8.8.8.0/24"
    assert result.timezone == "America/Los_Angeles"
    assert result.local_time == "2026-01-01T00:00:00"
    assert result.timezone_utc == "-08:00"
    assert result.currency == "USD"
    assert result.flag_emoji == "🇺🇸"
    assert result.is_proxy is False
    assert result.is_hosting is True
    assert result.threat_score == 0
    assert result.provider == "ipwhois"
    assert result.cached is False


@pytest.mark.unit
def test_ipwhois_429_raises_geoip_error(respx_mock):
    respx_mock.get("https://ipwho.is/8.8.8.8").mock(return_value=httpx.Response(429))

    provider = IPWhoIsProvider()
    with pytest.raises(GeoIPError, match="rate limit"):
        asyncio.run(provider.lookup("8.8.8.8"))


@pytest.mark.unit
def test_ipwhois_success_false_raises_geoip_error(respx_mock):
    payload = {"success": False, "message": "Invalid IP address"}
    respx_mock.get("https://ipwho.is/8.8.8.8").mock(return_value=httpx.Response(200, json=payload))

    provider = IPWhoIsProvider()
    with pytest.raises(GeoIPError, match="Invalid IP address"):
        asyncio.run(provider.lookup("8.8.8.8"))


@pytest.mark.unit
def test_ipwhois_success_false_generic_message(respx_mock):
    payload = {"success": False}
    respx_mock.get("https://ipwho.is/8.8.8.8").mock(return_value=httpx.Response(200, json=payload))

    provider = IPWhoIsProvider()
    with pytest.raises(GeoIPError, match="GeoIP lookup failed"):
        asyncio.run(provider.lookup("8.8.8.8"))


@pytest.mark.unit
def test_ipwhois_500_raises_http_status_error(respx_mock):
    respx_mock.get("https://ipwho.is/8.8.8.8").mock(return_value=httpx.Response(500))

    provider = IPWhoIsProvider()
    with pytest.raises(httpx.HTTPStatusError):
        asyncio.run(provider.lookup("8.8.8.8"))


@pytest.mark.unit
def test_ipwhois_no_lat_lon_produces_no_map_url(respx_mock):
    payload = {
        "success": True,
        "ip": "8.8.8.8",
        "country": "United States",
        "country_code": "US",
        "latitude": None,
        "longitude": None,
        "connection": {},
        "timezone": {},
        "currency": {},
        "flag": {},
        "security": {}
    }
    respx_mock.get("https://ipwho.is/8.8.8.8").mock(return_value=httpx.Response(200, json=payload))

    provider = IPWhoIsProvider()
    result = asyncio.run(provider.lookup("8.8.8.8"))

    assert result.map_url is None


@pytest.mark.unit
def test_ipwhois_null_connection_dict(respx_mock):
    payload = {
        "success": True,
        "ip": "8.8.8.8",
        "country": "United States",
        "country_code": "US",
        "latitude": 37.4056,
        "longitude": -122.0775,
        "connection": None,
        "timezone": {},
        "currency": {},
        "flag": {},
        "security": {}
    }
    respx_mock.get("https://ipwho.is/8.8.8.8").mock(return_value=httpx.Response(200, json=payload))

    provider = IPWhoIsProvider()
    result = asyncio.run(provider.lookup("8.8.8.8"))

    assert result.isp is None
    assert result.org is None
    assert result.asn is None


@pytest.mark.unit
def test_ipwhois_null_security_dict(respx_mock):
    payload = {
        "success": True,
        "ip": "8.8.8.8",
        "country": "United States",
        "country_code": "US",
        "latitude": 37.4056,
        "longitude": -122.0775,
        "connection": {},
        "timezone": {},
        "currency": {},
        "flag": {},
        "security": None
    }
    respx_mock.get("https://ipwho.is/8.8.8.8").mock(return_value=httpx.Response(200, json=payload))

    provider = IPWhoIsProvider()
    result = asyncio.run(provider.lookup("8.8.8.8"))

    assert result.is_proxy is None
    assert result.is_vpn is None


@pytest.mark.unit
def test_ipwhois_null_flag_dict(respx_mock):
    payload = {
        "success": True,
        "ip": "8.8.8.8",
        "country": "United States",
        "country_code": "US",
        "latitude": 37.4056,
        "longitude": -122.0775,
        "connection": {},
        "timezone": {},
        "currency": {},
        "flag": None,
        "security": {}
    }
    respx_mock.get("https://ipwho.is/8.8.8.8").mock(return_value=httpx.Response(200, json=payload))

    provider = IPWhoIsProvider()
    result = asyncio.run(provider.lookup("8.8.8.8"))

    assert result.flag_emoji is None
    assert result.flag_image is None


@pytest.mark.unit
def test_ipwhois_null_timezone_dict(respx_mock):
    payload = {
        "success": True,
        "ip": "8.8.8.8",
        "country": "United States",
        "country_code": "US",
        "latitude": 37.4056,
        "longitude": -122.0775,
        "connection": {},
        "timezone": None,
        "currency": {},
        "flag": {},
        "security": {}
    }
    respx_mock.get("https://ipwho.is/8.8.8.8").mock(return_value=httpx.Response(200, json=payload))

    provider = IPWhoIsProvider()
    result = asyncio.run(provider.lookup("8.8.8.8"))

    assert result.timezone is None
    assert result.local_time is None


@pytest.mark.unit
def test_ipwhois_null_currency_dict(respx_mock):
    payload = {
        "success": True,
        "ip": "8.8.8.8",
        "country": "United States",
        "country_code": "US",
        "latitude": 37.4056,
        "longitude": -122.0775,
        "connection": {},
        "timezone": {},
        "currency": None,
        "flag": {},
        "security": {}
    }
    respx_mock.get("https://ipwho.is/8.8.8.8").mock(return_value=httpx.Response(200, json=payload))

    provider = IPWhoIsProvider()
    result = asyncio.run(provider.lookup("8.8.8.8"))

    assert result.currency is None


@pytest.mark.unit
def test_ipwhois_timeout_propagates_as_timeout_exception(respx_mock):
    respx_mock.get("https://ipwho.is/8.8.8.8").mock(side_effect=httpx.TimeoutException("timed out"))

    provider = IPWhoIsProvider()
    with pytest.raises(httpx.TimeoutException, match="timed out"):
        asyncio.run(provider.lookup("8.8.8.8"))
