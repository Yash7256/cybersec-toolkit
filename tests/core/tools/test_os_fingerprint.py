"""
Tests for cybersec/core/tools/os_fingerprint.py

Coverage:
  (a) Private-IP target is blocked before _read_ttl / geoip_lookup / scan_ports are called.
  (b) scan_ports() is invoked with include_ai_recommendations=False and
      include_threat_intel=False (and include_misconfigurations=False,
      include_screenshots=False) from os_fingerprint().
  (c) eol_findings / vulnerability_correlation are populated from a mocked
      OpenPortDetail.cve_result rather than banner substrings.
"""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cybersec.core.tools.os_fingerprint import os_fingerprint, _eol_and_vuln_findings
from cybersec.core.tools.port_scanner import OpenPortDetail


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_port(
    port_number: int,
    version: str | None = None,
    cve_total: int = 0,
    cve_critical: int = 0,
    cve_high: int = 0,
) -> OpenPortDetail:
    port = OpenPortDetail(
        port_number=port_number,
        service="http",
        status="open",
        version=version,
    )
    if cve_total:
        cve = MagicMock()
        cve.total_count = cve_total
        cve.critical_count = cve_critical
        cve.high_count = cve_high
        cve.medium_count = 0
        cve.low_count = 0
        cve.cves = []
        port.cve_result = cve
        port.cve_count = cve_total
        port.cve_critical_count = cve_critical
        port.cve_high_count = cve_high
    return port


def _dummy_ports_result():
    from cybersec.core.tools.port_scanner import PortScanResult
    return PortScanResult(
        target="example.com",
        total_scanned=0,
        open_ports_count=0,
        open_ports=[],
        scan_duration_seconds=0.0,
        error=None,
    )


# ---------------------------------------------------------------------------
# Test (a): private IP — nothing fires after the SSRF guard
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_private_ip_blocked_before_ttl_geo_scan():
    """
    When the resolved IP is private, os_fingerprint() must return an error
    result immediately without ever calling _read_ttl, geoip_lookup, or scan_ports.
    """
    ttl_mock = AsyncMock()
    geo_mock = AsyncMock()
    scan_mock = AsyncMock()

    with (
        patch("cybersec.core.tools.os_fingerprint._resolve_ipv4",
              AsyncMock(return_value=("192.168.1.1", None))),
        patch("cybersec.core.tools.os_fingerprint._read_ttl", ttl_mock),
        patch("cybersec.core.tools.os_fingerprint.geoip_lookup", geo_mock),
        patch("cybersec.core.tools.os_fingerprint.scan_ports", scan_mock),
    ):
        result = await os_fingerprint("192.168.1.1", timeout=2.0)

    ttl_mock.assert_not_called()
    geo_mock.assert_not_called()
    scan_mock.assert_not_called()
    assert result.error is not None
    assert "permitted" in result.error.lower() or "private" in result.error.lower()
    assert result.confidence == 0


# ---------------------------------------------------------------------------
# Test (b): scan_ports called with all four skip flags False
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_scan_ports_called_with_skip_flags():
    """
    os_fingerprint() must call scan_ports() with
    include_ai_recommendations=False, include_threat_intel=False,
    include_misconfigurations=False, include_screenshots=False.
    """
    scan_mock = AsyncMock(return_value=_dummy_ports_result())
    geo_mock = AsyncMock(return_value=MagicMock(
        country=None, country_code=None, city=None, region=None,
        lat=None, lon=None, asn=None, org=None, isp=None,
        timezone=None, is_hosting=False, rdap_name=None,
        reverse_dns=None, asn_domain=None, asn_type=None, error=None,
    ))

    with (
        patch("cybersec.core.tools.os_fingerprint._resolve_ipv4",
              AsyncMock(return_value=("1.2.3.4", None))),
        patch("cybersec.core.tools.os_fingerprint._read_ttl", AsyncMock(return_value=64)),
        patch("cybersec.core.tools.os_fingerprint.geoip_lookup", geo_mock),
        patch("cybersec.core.tools.os_fingerprint.scan_ports", scan_mock),
        patch("cybersec.core.tools.os_fingerprint._tcp_probe",
              AsyncMock(return_value={"mss": None, "note": "test"})),
        patch("cybersec.core.tools.os_fingerprint.dataclasses.asdict",
              MagicMock(return_value={
                  "country": None, "country_code": None, "city": None,
                  "org": None, "isp": None, "asn": None, "asn_domain": None,
                  "asn_type": None, "rdap_name": None, "reverse_dns": None,
                  "is_hosting": False,
              })),
    ):
        await os_fingerprint("example.com", timeout=2.0)

    scan_mock.assert_called_once()
    kwargs = scan_mock.call_args.kwargs
    assert kwargs.get("include_ai_recommendations") is False
    assert kwargs.get("include_threat_intel") is False
    assert kwargs.get("include_misconfigurations") is False
    assert kwargs.get("include_screenshots") is False


# ---------------------------------------------------------------------------
# Test (c): _eol_and_vuln_findings uses cve_result, not banner substrings
# ---------------------------------------------------------------------------

def test_eol_and_vuln_findings_critical_cve():
    """
    A port with critical CVEs produces a 'critical' vuln entry and an
    Aged eol entry — driven by CVE data, not banner text.
    """
    port = _make_port(80, version="nginx/1.18.0", cve_total=3, cve_critical=2, cve_high=1)
    eol, vulns = _eol_and_vuln_findings([port])

    assert len(vulns) == 1
    assert vulns[0]["severity"] == "critical"
    assert "nginx/1.18.0" == vulns[0]["component"]
    assert len(eol) == 1
    assert eol[0]["status"] == "Aged"


def test_eol_and_vuln_findings_banner_fallback_when_no_cve_result():
    """
    When cve_result is None the banner fallback must still fire for
    the Apache 2.4.7 pattern.
    """
    port = _make_port(80, version="Apache/2.4.7")
    port.raw_banner = "HTTP/1.1 200 OK\r\nServer: Apache/2.4.7\r\n"
    assert port.cve_result is None

    eol, vulns = _eol_and_vuln_findings([port])

    assert any("Apache" in e["component"] for e in eol)
    assert any("Apache" in v["component"] for v in vulns)


def test_eol_and_vuln_findings_high_cve_only():
    """High-only CVEs produce severity='high'."""
    port = _make_port(443, version="OpenSSL/1.0.2", cve_total=2, cve_critical=0, cve_high=2)
    eol, vulns = _eol_and_vuln_findings([port])

    assert vulns[0]["severity"] == "high"
    assert vulns[0]["component"] == "OpenSSL/1.0.2"


# ---------------------------------------------------------------------------
# Test (d): Redis cache hit — second call returns cached result, no live work
# ---------------------------------------------------------------------------

def _make_live_mocks():
    """Return (ttl_mock, geo_mock, scan_mock, tcp_mock) pre-configured for a live run."""
    from cybersec.core.tools.port_scanner import PortScanResult
    ports_result = PortScanResult(
        target="example.com",
        total_scanned=0,
        open_ports_count=0,
        open_ports=[],
        scan_duration_seconds=0.1,
        error=None,
    )
    geo_obj = MagicMock(
        country=None, country_code=None, city=None, region=None,
        lat=None, lon=None, asn=None, org=None, isp=None,
        timezone=None, is_hosting=False, rdap_name=None,
        reverse_dns=None, asn_domain=None, asn_type=None, error=None,
    )
    return (
        AsyncMock(return_value=64),                # _read_ttl
        AsyncMock(return_value=geo_obj),           # geoip_lookup
        AsyncMock(return_value=ports_result),       # scan_ports
        AsyncMock(return_value={"mss": None, "note": "test"}),  # _tcp_probe
    )


@pytest.mark.asyncio
async def test_cache_hit_skips_live_scan():
    """
    Second call for the same target within the TTL window must return the
    cached result without invoking _read_ttl, geoip_lookup, or scan_ports.
    """
    import dataclasses, json
    from cybersec.core.tools.os_fingerprint import OsFingerprintResult

    ttl_mock, geo_mock, scan_mock, tcp_mock = _make_live_mocks()

    # Build a minimal OsFingerprintResult that can be serialised and fed back.
    cached_result = OsFingerprintResult(
        target="example.com",
        ip="1.2.3.4",
        detected_os="Linux/Unix-like",
        family="unix",
        os_version_estimate=None,
        distribution_family=None,
        kernel_estimate=None,
        device_type="Server",
        environment="Unknown",
        hosting_provider=None,
        confidence=50,
        confidence_label="Moderate",
        method="cached",
        detection_mode="Passive Fingerprinting",
        cached=False,
    )
    cached_json = json.dumps(dataclasses.asdict(cached_result))

    # Redis mock: first call (GET) returns the serialised result → cache hit.
    redis_mock = AsyncMock()
    redis_mock.get = AsyncMock(return_value=cached_json)

    with (
        patch("cybersec.core.tools.os_fingerprint._resolve_ipv4",
              AsyncMock(return_value=("1.2.3.4", None))),
        patch("cybersec.core.tools.os_fingerprint.get_shared_redis_client",
              return_value=redis_mock),
        patch("cybersec.core.tools.os_fingerprint._read_ttl", ttl_mock),
        patch("cybersec.core.tools.os_fingerprint.geoip_lookup", geo_mock),
        patch("cybersec.core.tools.os_fingerprint.scan_ports", scan_mock),
        patch("cybersec.core.tools.os_fingerprint._tcp_probe", tcp_mock),
    ):
        result = await os_fingerprint("example.com", timeout=2.0)

    # Live work must not have been triggered.
    ttl_mock.assert_not_called()
    geo_mock.assert_not_called()
    scan_mock.assert_not_called()
    tcp_mock.assert_not_called()

    # The result must be flagged as cached.
    assert result.cached is True
    assert result.detected_os == "Linux/Unix-like"


@pytest.mark.asyncio
async def test_cache_miss_triggers_live_scan_and_writes_cache():
    """
    When Redis returns None (cache miss), os_fingerprint() must run a live
    scan and write the result back to Redis.
    """
    ttl_mock, geo_mock, scan_mock, tcp_mock = _make_live_mocks()

    redis_mock = AsyncMock()
    redis_mock.get = AsyncMock(return_value=None)   # cache miss
    redis_mock.set = AsyncMock()

    with (
        patch("cybersec.core.tools.os_fingerprint._resolve_ipv4",
              AsyncMock(return_value=("1.2.3.4", None))),
        patch("cybersec.core.tools.os_fingerprint.get_shared_redis_client",
              return_value=redis_mock),
        patch("cybersec.core.tools.os_fingerprint._read_ttl", ttl_mock),
        patch("cybersec.core.tools.os_fingerprint.geoip_lookup", geo_mock),
        patch("cybersec.core.tools.os_fingerprint.scan_ports", scan_mock),
        patch("cybersec.core.tools.os_fingerprint._tcp_probe", tcp_mock),
        patch("cybersec.core.tools.os_fingerprint.dataclasses.asdict",
              MagicMock(return_value={
                  "country": None, "country_code": None, "city": None,
                  "org": None, "isp": None, "asn": None, "asn_domain": None,
                  "asn_type": None, "rdap_name": None, "reverse_dns": None,
                  "is_hosting": False,
              })),
    ):
        result = await os_fingerprint("example.com", timeout=2.0)

    # Live scan must have fired exactly once.
    ttl_mock.assert_called_once()
    scan_mock.assert_called_once()

    # Cache write must have been attempted.
    redis_mock.set.assert_called_once()
    set_args = redis_mock.set.call_args
    assert set_args.kwargs.get("ex") == 1800 or (len(set_args.args) >= 3 and set_args.args[2] == 1800) or set_args.kwargs.get("ex") is not None

    assert result.cached is False


@pytest.mark.asyncio
async def test_expired_cache_triggers_fresh_scan():
    """
    A None from Redis (entry absent / expired TTL) must cause a full live scan,
    identical to a cold miss — the TTL expiry is handled by Redis itself.
    """
    ttl_mock, geo_mock, scan_mock, tcp_mock = _make_live_mocks()

    redis_mock = AsyncMock()
    redis_mock.get = AsyncMock(return_value=None)  # expired → absent from Redis
    redis_mock.set = AsyncMock()

    with (
        patch("cybersec.core.tools.os_fingerprint._resolve_ipv4",
              AsyncMock(return_value=("5.6.7.8", None))),
        patch("cybersec.core.tools.os_fingerprint.get_shared_redis_client",
              return_value=redis_mock),
        patch("cybersec.core.tools.os_fingerprint._read_ttl", ttl_mock),
        patch("cybersec.core.tools.os_fingerprint.geoip_lookup", geo_mock),
        patch("cybersec.core.tools.os_fingerprint.scan_ports", scan_mock),
        patch("cybersec.core.tools.os_fingerprint._tcp_probe", tcp_mock),
        patch("cybersec.core.tools.os_fingerprint.dataclasses.asdict",
              MagicMock(return_value={
                  "country": None, "country_code": None, "city": None,
                  "org": None, "isp": None, "asn": None, "asn_domain": None,
                  "asn_type": None, "rdap_name": None, "reverse_dns": None,
                  "is_hosting": False,
              })),
    ):
        result = await os_fingerprint("expiredhost.example.com", timeout=2.0)

    # All three live-scan helpers must fire.
    ttl_mock.assert_called_once()
    geo_mock.assert_called_once()
    scan_mock.assert_called_once()

    # Fresh result is not flagged as cached.
    assert result.cached is False
    # Cache was re-populated.
    redis_mock.set.assert_called_once()

