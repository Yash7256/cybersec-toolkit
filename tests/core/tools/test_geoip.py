import asyncio

import httpx
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
            isp="Example ISP",
            org="Example Org",
            asn="AS12345",
            asn_route=None,
            asn_domain="example.com",
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
async def clear_cache(monkeypatch):
    async def fake_rdap(ip):
        return {}

    async def fake_reverse_dns(ip):
        return None

    monkeypatch.setattr(geoip, "_fetch_rdap", fake_rdap)
    monkeypatch.setattr(geoip, "_reverse_dns", fake_reverse_dns)
    geoip._http_client = None
    # Reset rate limiter
    geoip._geoip_rate_limiter = geoip._RateLimiter(55)
    await geoip.clear_geoip_cache()
    
    # Register default providers for tests
    geoip.register_geoip_provider(geoip.IPWhoIsProvider())
    geoip.register_geoip_provider(geoip.IPApiProvider())
    
    yield
    geoip._http_client = None
    # Reset rate limiter
    geoip._geoip_rate_limiter = geoip._RateLimiter(55)
    await geoip.clear_geoip_cache()
    # Clear providers
    geoip._PROVIDERS.clear()


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
    assert second.as_number == "AS12345"
    assert first.ip_results[0]["summary"] == "8.8.8.8 resolves to 8.8.8.8 on Example Org in United States."
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
        result.is_proxy = None
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


def test_geoip_lookup_runs_reverse_dns_and_rdap_concurrently(monkeypatch):
    import time
    provider = FakeProvider()
    geoip.register_geoip_provider(provider)

    async def delayed_reverse_dns(ip):
        await asyncio.sleep(0.1)
        return "dns.google"

    async def delayed_apply_rdap(ip):
        await asyncio.sleep(0.1)
        from cybersec.core.tools.geoip import RDAPData
        return RDAPData(
            rdap_name="TEST",
            rdap_handle="TEST-HANDLE",
            rdap_registry="ARIN",
            rdap_cidr="8.8.8.0/24",
            rdap_country="US",
            rdap_start_address="8.8.8.0",
            rdap_end_address="8.8.8.255",
            rdap_abuse_email="abuse@test.com",
            rdap_abuse_phone=None,
            rdap_events=[],
            abuse_contact="abuse@test.com",
        )

    monkeypatch.setattr(geoip, "_reverse_dns", delayed_reverse_dns)
    monkeypatch.setattr(geoip, "_apply_rdap", delayed_apply_rdap)

    start_time = time.time()
    result = asyncio.run(geoip.geoip_lookup("8.8.8.8", provider_name="fake"))
    total_time = time.time() - start_time

    assert result.error is None
    assert result.reverse_dns == "dns.google"
    assert result.rdap_name == "TEST"
    # Verify total time is closer to max(0.1, 0.1) = 0.1s, not sum=0.2s
    assert total_time < 0.18, f"Expected total time < 0.18s, got {total_time}s"


def test_geoip_lookup_handles_multiple_ips_concurrently(monkeypatch):
    import time
    provider = FakeProvider()
    geoip.register_geoip_provider(provider)
    
    # Mock _resolve_target to return multiple IPs
    async def fake_resolve(target):
        # Return 4 IPs: 8.8.8.8, 8.8.8.9, 8.8.8.10, 8.8.8.11
        return "8.8.8.8", ["8.8.8.8", "8.8.8.9", "8.8.8.10", "8.8.8.11"]
    monkeypatch.setattr(geoip, "_resolve_target", fake_resolve)
    
    # Mock _apply_rdap to return RDAPData with rdap_name set
    async def fake_apply_rdap(ip):
        from cybersec.core.tools.geoip import RDAPData
        return RDAPData(
            rdap_name=f"TEST-{ip}",
            rdap_handle=None,
            rdap_registry=None,
            rdap_cidr=None,
            rdap_country=None,
            rdap_start_address=None,
            rdap_end_address=None,
            rdap_abuse_email=None,
            rdap_abuse_phone=None,
            rdap_events=[],
            abuse_contact=None,
        )
    monkeypatch.setattr(geoip, "_apply_rdap", fake_apply_rdap)
    
    # Mock _reverse_dns to avoid issues
    async def fake_reverse_dns(ip):
        return None
    monkeypatch.setattr(geoip, "_reverse_dns", fake_reverse_dns)
    
    # Modify FakeProvider to add a distinct field for each IP and add delay
    original_lookup = provider.lookup
    call_count = 0
    
    async def delayed_lookup(ip):
        nonlocal call_count
        await asyncio.sleep(0.2)
        # Make 8.8.8.10 raise an exception to test error isolation
        if ip == "8.8.8.10":
            raise RuntimeError("IP lookup failed for test")
        result = await original_lookup(ip)
        call_count += 1
        result.rdap_name = f"TEST-{ip}"  # Add distinct field
        return result
    provider.lookup = delayed_lookup
    
    start_time = time.time()
    result = asyncio.run(geoip.geoip_lookup("test.example.com", provider_name="fake"))
    total_time = time.time() - start_time
    
    # Verify total time is under 4x0.2s
    assert total_time < 0.5, f"Expected total time < 0.5s, got {total_time}s"
    
    # Verify ip_results order matches resolved_ips
    expected_order = ["test.example.com", "8.8.8.9", "8.8.8.10", "8.8.8.11"]
    actual_order = [item["target"] for item in result.ip_results]
    assert actual_order == expected_order
    
    # Verify 8.8.8.10 has error in ip_results
    assert "Failed to lookup 8.8.8.10" in result.ip_results[2]["error"] or "All providers failed" in result.ip_results[2]["error"]
    # Verify other IPs have expected rdap_name
    assert result.ip_results[1]["rdap_name"] == "TEST-8.8.8.9"
    assert result.ip_results[3]["rdap_name"] == "TEST-8.8.8.11"


def test_geoip_rate_limiter_throttles_calls(monkeypatch):
    import time

    # Track sleep calls
    sleep_calls = []
    current_time = 0.0

    def mock_time():
        return current_time

    async def mock_sleep(seconds):
        nonlocal current_time
        sleep_calls.append(seconds)
        current_time += seconds  # Advance time by the sleep duration

    monkeypatch.setattr(time, "time", mock_time)
    monkeypatch.setattr(asyncio, "sleep", mock_sleep)

    # Test _RateLimiter directly
    limiter = geoip._RateLimiter(2)  # 2 per minute

    # Issue 3 concurrent acquire calls
    async def test_throttle():
        tasks = [limiter.acquire() for _ in range(3)]
        await asyncio.gather(*tasks)

    asyncio.run(test_throttle())

    # Check that we had at least one sleep call
    assert len(sleep_calls) >= 1
    # Check that the sleep duration makes sense
    assert any(0 < t <= 60 for t in sleep_calls)


def test_geoip_fallback_primary_fails(monkeypatch):
    from unittest.mock import AsyncMock
    from cybersec.config import settings
    
    # Create a fake result that will be returned by ipapi
    fake_provider = FakeProvider()
    fake_result = asyncio.run(fake_provider.lookup("8.8.8.8"))
    fake_result.provider = "ipapi"  # Override to match the provider that succeeds
    
    # Mock ipwhois to fail, ipapi to succeed
    async def failing_lookup(target):
        raise httpx.HTTPStatusError(
            message="test error",
            request=AsyncMock(),
            response=AsyncMock(status_code=503)
        )
    
    async def succeeding_lookup(target):
        return fake_result
    
    geoip._PROVIDERS["ipwhois"].lookup = failing_lookup
    geoip._PROVIDERS["ipapi"].lookup = succeeding_lookup
    
    # Clear cache
    geoip.clear_geoip_cache()
    
    # Perform lookup
    result = asyncio.run(geoip.geoip_lookup("8.8.8.8"))
    
    # Verify
    assert result.provider == "ipapi"
    assert "Fell back" in result.infrastructure_note


def test_geoip_no_fallback_client_error(monkeypatch):
    from unittest.mock import AsyncMock
    
    # Mock ipwhois to give client error
    async def failing_lookup(target):
        raise httpx.HTTPStatusError(
            message="test error",
            request=AsyncMock(),
            response=AsyncMock(status_code=400)
        )
    
    geoip._PROVIDERS["ipwhois"].lookup = failing_lookup
    
    # Track if ipapi was called
    ipapi_called = False
    original_ipapi_lookup = geoip._PROVIDERS["ipapi"].lookup
    
    async def tracking_lookup(target):
        nonlocal ipapi_called
        ipapi_called = True
        return await original_ipapi_lookup(target)
    
    geoip._PROVIDERS["ipapi"].lookup = tracking_lookup
    
    # Clear cache
    geoip.clear_geoip_cache()
    
    # Perform lookup
    result = asyncio.run(geoip.geoip_lookup("invalid"))
    
    # Verify no fallback (ipapi wasn't called)
    assert ipapi_called is False


def test_geoip_all_providers_fail(monkeypatch):
    from unittest.mock import AsyncMock
    
    # Mock both providers to fail
    async def failing_ipwhois(target):
        raise Exception("ipwhois failed")
    
    async def failing_ipapi(target):
        raise Exception("ipapi failed")
    
    geoip._PROVIDERS["ipwhois"].lookup = failing_ipwhois
    geoip._PROVIDERS["ipapi"].lookup = failing_ipapi
    
    # Clear cache
    geoip.clear_geoip_cache()
    
    # Perform lookup
    result = asyncio.run(geoip.geoip_lookup("8.8.8.8"))
    
    # Verify combined error
    assert "All providers failed" in result.error
    assert "ipwhois: ipwhois failed" in result.error
    assert "ipapi: ipapi failed" in result.error


def test_cache_max_size_bound(monkeypatch):
    """Test that cache never exceeds GEOIP_CACHE_MAX_ENTRIES."""
    from cybersec.config import settings
    
    # Temporarily reduce max size for test
    original_max = settings.GEOIP_CACHE_MAX_ENTRIES
    monkeypatch.setattr(settings, "GEOIP_CACHE_MAX_ENTRIES", 5)
    
    # Reinitialize cache with new max size
    geoip._CACHE = geoip._LRUCache(max_size=5)
    
    # Insert more entries than max size
    async def insert_entries():
        for i in range(10):
            result = await FakeProvider().lookup(f"1.2.3.{i}")
            key = geoip._cache_key("fake", f"1.2.3.{i}")
            await geoip._CACHE.set(key, 9999999999.0, result)
    
    asyncio.run(insert_entries())
    
    # Verify cache size never exceeds max
    assert geoip._CACHE.size() <= 5
    
    # Restore original max size
    monkeypatch.setattr(settings, "GEOIP_CACHE_MAX_ENTRIES", original_max)


def test_cache_periodic_sweep(monkeypatch):
    """Test that periodic sweep removes expired entries."""
    import time as time_module
    
    # Insert entries with different expiry times
    now = 1000.0
    
    async def insert_entries():
        for i in range(5):
            result = await FakeProvider().lookup(f"1.2.3.{i}")
            key = geoip._cache_key("fake", f"1.2.3.{i}")
            # First 3 entries expired, last 2 not expired
            expiry = now - 10.0 if i < 3 else now + 1000.0
            await geoip._CACHE.set(key, expiry, result)
    
    asyncio.run(insert_entries())
    
    # Verify initial size
    assert geoip._CACHE.size() == 5
    
    # Sweep expired entries
    removed = asyncio.run(geoip._CACHE.sweep_expired(now))
    
    # Verify 3 expired entries were removed
    assert removed == 3
    assert geoip._CACHE.size() == 2
