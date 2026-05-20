import asyncio

import pytest

from cybersec.core.tools import geoip
from cybersec.core.tools.geoip import GeoIPError, GeoIPResult


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


class FailingProvider:
    name = "failing"

    async def lookup(self, target: str) -> GeoIPResult:
        raise GeoIPError("provider said no")


@pytest.fixture(autouse=True)
def clear_cache(monkeypatch):
    async def fake_rdap(ip):
        return {}

    async def fake_reverse_dns(ip):
        return None

    monkeypatch.setattr(geoip, "_fetch_rdap", fake_rdap)
    monkeypatch.setattr(geoip, "_reverse_dns", fake_reverse_dns)
    geoip.clear_geoip_cache()
    yield
    geoip.clear_geoip_cache()


def test_geoip_lookup_success_and_cache():
    provider = FakeProvider()
    geoip.register_geoip_provider(provider)

    first = asyncio.run(geoip.geoip_lookup("8.8.8.8", provider_name="fake"))
    second = asyncio.run(geoip.geoip_lookup("8.8.8.8", provider_name="fake"))

    assert first.error is None
    assert first.country_code == "US"
    assert first.cached is False
    assert second.cached is True
    assert second.latitude == 37.4056
    assert second.as_number == "AS15169 Google LLC"
    assert first.ip_results[0]["summary"] == "8.8.8.8 resolves to 8.8.8.8 on Google Public DNS in United States."
    assert provider.calls == 1


def test_geoip_hostname_resolution(monkeypatch):
    provider = FakeProvider()
    geoip.register_geoip_provider(provider)

    async def fake_resolve(target):
        assert target == "example.com"
        return "8.8.8.8", ["8.8.8.8", "2001:4860:4860::8888"]

    monkeypatch.setattr(geoip, "_resolve_target", fake_resolve)
    async def fake_reverse_dns(ip):
        return "dns.google"

    monkeypatch.setattr(geoip, "_reverse_dns", fake_reverse_dns)

    result = asyncio.run(geoip.geoip_lookup("example.com", provider_name="fake"))

    assert result.error is None
    assert result.target == "example.com"
    assert result.ip == "8.8.8.8"
    assert result.resolved_ips == ["8.8.8.8", "2001:4860:4860::8888"]
    assert result.reverse_dns == "dns.google"


def test_geoip_detects_cdn_and_applies_rdap(monkeypatch):
    provider = FakeProvider()
    geoip.register_geoip_provider(provider)

    async def fake_rdap(ip):
        return {
            "name": "CLOUDFLARENET",
            "handle": "NET-104-16-0-0-1",
            "country": "US",
            "startAddress": "104.16.0.0",
            "endAddress": "104.31.255.255",
            "cidr0_cidrs": [{"v4prefix": "104.16.0.0", "length": 12}],
            "notices": [{"title": "ARIN WHOIS data and services"}],
            "entities": [
                {
                    "roles": ["abuse"],
                    "vcardArray": ["vcard", [["email", {}, "text", "abuse@example.com"]]],
                }
            ],
            "events": [{"eventAction": "registration", "eventDate": "2014-03-28T00:00:00Z"}],
        }

    original_lookup = provider.lookup

    async def fake_lookup(target):
        result = await original_lookup(target)
        result.org = "Cloudflare, Inc."
        result.isp = "Cloudflare, Inc."
        result.asn = "AS13335"
        result.asn_domain = "cloudflare.com"
        return result

    provider.lookup = fake_lookup
    monkeypatch.setattr(geoip, "_fetch_rdap", fake_rdap)

    result = asyncio.run(geoip.geoip_lookup("104.21.82.144", provider_name="fake"))

    assert result.is_cdn is True
    assert result.cdn_provider == "Cloudflare"
    assert result.is_proxy is True
    assert result.rdap_cidr == "104.16.0.0/12"
    assert result.abuse_contact == "abuse@example.com"


def test_geoip_blocks_private_ip_targets():
    result = asyncio.run(geoip.geoip_lookup("127.0.0.1", provider_name="fake"))

    assert "not sent to external GeoIP providers" in result.error


def test_geoip_unsupported_provider():
    result = asyncio.run(geoip.geoip_lookup("8.8.8.8", provider_name="missing"))

    assert result.error == "Unsupported GeoIP provider: missing"


def test_geoip_provider_error_is_returned():
    geoip.register_geoip_provider(FailingProvider())

    result = asyncio.run(geoip.geoip_lookup("8.8.8.8", provider_name="failing"))

    assert result.error == "provider said no"
