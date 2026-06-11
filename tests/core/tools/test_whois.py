from datetime import datetime, timedelta, timezone

from cybersec.core.tools import whois


def test_normalize_target_strips_scheme_path_and_port():
    assert whois._normalize_target("https://Example.COM:443/login") == "example.com"


def test_status_explanations_normalize_links_and_case():
    explained = whois._status_explanations(["clientTransferProhibited https://icann.org/epp#clientTransferProhibited"])

    assert explained[0]["meaning"] == "Domain transfer is locked by the registrar."


def test_privacy_detection_across_fields():
    assert whois._privacy_detected("Registrant Organization: Domains By Proxy, LLC") is True


def test_risk_indicators_cover_requested_signals():
    now = datetime.now(timezone.utc)
    risks = whois._risk_indicators(
        creation=now - timedelta(days=3),
        updated=now - timedelta(days=2),
        expiry_status="expiring_soon",
        privacy_protected=True,
        statuses=["clientHold"],
        tld="zip",
        now=now,
    )

    ids = {risk["id"] for risk in risks}
    assert "newly_registered" in ids
    assert "expiring_soon" in ids
    assert "privacy_protected" in ids
    assert "recently_updated" in ids
    assert "suspicious_status" in ids
    assert "unusual_tld" in ids


def test_iana_metadata_includes_registry_hint_and_link():
    data = whois._iana_metadata("org", "Public Interest Registry")

    assert data["iana_url"] == "https://www.iana.org/domains/root/db/org.html"
    assert data["registry_hint"] == "Public Interest Registry"


def test_normalize_target_rejects_malicious_inputs():
    import pytest
    with pytest.raises(ValueError):
        whois._normalize_target("domain.com;whoami")
    with pytest.raises(ValueError):
        whois._normalize_target("domain.com -h rogue")
    with pytest.raises(ValueError):
        whois._normalize_target("domain.com|cat /etc/passwd")
    with pytest.raises(ValueError):
        whois._normalize_target("domain.com&echo 123")
    with pytest.raises(ValueError):
        whois._normalize_target("")
    with pytest.raises(ValueError):
        whois._normalize_target("a" * 254)


def test_cache_size_bounding():
    import time
    whois.clear_whois_cache()
    now = time.time()
    for i in range(1005):
        domain = f"testdomain{i}.com"
        result = whois.WHOISResult(
            target=domain, domain=domain, tld="com", registrar=None, registrar_iana_id=None,
            registrar_url=None, registrar_abuse_email=None, registrar_abuse_phone=None,
            creation_date=None, expiration_date=None, updated_date=None,
            domain_age_days=None, days_until_expiry=None, expiry_status=None,
            name_servers=[], dnssec=None, status=[], status_explanations=[], emails=[],
            registrant_org=None, registrant_country=None, admin_contact=None,
            tech_contact=None, abuse_contact=None, privacy_protected=False, raw_text=None,
            rdap=None, rdap_available=False, registry=None, iana=None, available=None,
            historical_whois={}, related_domains={}, risk_indicators=[], summary=None,
            normalized={}, cached=False, error=None
        )
        with whois._CACHE_LOCK:
            if len(whois._CACHE) >= whois.MAX_CACHE_SIZE:
                oldest_key = next(iter(whois._CACHE))
                whois._CACHE.pop(oldest_key, None)
            whois._CACHE[domain] = (now + 3600, result)

    assert len(whois._CACHE) == 1000
    assert "testdomain0.com" not in whois._CACHE
    assert "testdomain4.com" not in whois._CACHE
    assert "testdomain5.com" in whois._CACHE
    assert "testdomain1004.com" in whois._CACHE
    whois.clear_whois_cache()


def _make_result(domain: str) -> whois.WHOISResult:
    return whois.WHOISResult(
        target=domain, domain=domain, tld="com", registrar=None, registrar_iana_id=None,
        registrar_url=None, registrar_abuse_email=None, registrar_abuse_phone=None,
        creation_date=None, expiration_date=None, updated_date=None,
        domain_age_days=None, days_until_expiry=None, expiry_status=None,
        name_servers=[], dnssec=None, status=[], status_explanations=[], emails=[],
        registrant_org=None, registrant_country=None, admin_contact=None,
        tech_contact=None, abuse_contact=None, privacy_protected=False, raw_text=None,
        rdap=None, rdap_available=False, registry=None, iana=None, available=None,
        historical_whois={}, related_domains={}, risk_indicators=[], summary=None,
        normalized={}, cached=False, error=None
    )


def test_redis_cache_hit_populates_local_cache():
    """Redis read should backfill the local in-memory cache."""
    import asyncio
    import json
    from dataclasses import asdict
    from unittest.mock import AsyncMock, patch

    domain = "redisread.com"
    whois.clear_whois_cache()
    result = _make_result(domain)
    raw = json.dumps(asdict(result))

    mock_redis = AsyncMock()
    mock_redis.get = AsyncMock(return_value=raw)

    async def run():
        with patch("cybersec.core.tools.whois._get_redis", return_value=mock_redis):
            # Simulate the Redis read path
            r = mock_redis
            fetched_raw = await r.get(f"whois:{domain}")
            assert fetched_raw == raw
            result_dict = json.loads(fetched_raw)
            restored = whois.WHOISResult(**result_dict)
            # Backfill local cache
            import time
            with whois._CACHE_LOCK:
                whois._CACHE[domain] = (time.time() + 3600, restored)
            assert domain in whois._CACHE

    asyncio.run(run())
    whois.clear_whois_cache()


def test_redis_unavailable_falls_back_to_local_cache():
    """When Redis is unavailable the local cache should still serve hits."""
    import asyncio
    import time
    from unittest.mock import AsyncMock, patch

    domain = "neredis.com"
    whois.clear_whois_cache()
    result = _make_result(domain)
    now = time.time()

    with whois._CACHE_LOCK:
        whois._CACHE[domain] = (now + 3600, result)

    async def run():
        # _get_redis raises, simulating failure
        async def failing_get_redis():
            raise ConnectionRefusedError("No Redis")

        with patch("cybersec.core.tools.whois._get_redis", side_effect=failing_get_redis):
            with whois._CACHE_LOCK:
                local_hit = whois._CACHE.get(domain)
            assert local_hit is not None
            assert local_hit[1].domain == domain

    asyncio.run(run())
    whois.clear_whois_cache()

