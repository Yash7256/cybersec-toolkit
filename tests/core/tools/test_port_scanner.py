"""
Tests for cybersec/core/tools/port_scanner.py

Coverage:
  - Parallelization: detect_cves_batch, detect_misconfigurations,
    and check_threat_intelligence run concurrently via asyncio.gather —
    total elapsed time ≈ max(N) rather than sum(N).
  - ssl_audit deduplication: called exactly once per unique HTTPS port for a
    scan that finds port 443 open, shared between detect_misconfigurations and
    calculate_security_score.
"""
import asyncio
import time
from dataclasses import dataclass, field
from unittest.mock import AsyncMock, MagicMock, patch, call

import pytest

import cybersec.core.tools.port_scanner as ps_mod
from cybersec.core.tools.port_scanner import (
    OpenPortDetail,
    scan_ports,
    stream_port_scan_events,
)


# ---------------------------------------------------------------------------
# Minimal stubs for types returned by collaborators
# ---------------------------------------------------------------------------

def _make_open_port(port_number: int, service: str = "http", version: str | None = None) -> OpenPortDetail:
    return OpenPortDetail(
        port_number=port_number,
        service=service,
        status="open",
        risk_level="low",
        risk_reason="test",
        version=version,
    )


def _dummy_ssl_result(port: int):
    """Return a minimal SSLResult-like object that won't trigger score penalties."""
    from cybersec.core.tools.ssl import SSLResult
    return SSLResult(
        host="example.com",
        port=port,
        tls_version="TLSv1.3",
        cipher_suite="TLS_AES_256_GCM_SHA384",
        cert=None,
        is_self_signed=False,
        supports_tls12=True,
        supports_tls13=True,
        error=None,
    )


def _dummy_threat_intel():
    return {
        "ip": "1.2.3.4",
        "reputation": "clean",
        "summary": "No threat intelligence data.",
        "reported_times": 0,
        "abuse_confidence_score": None,
        "abuseipdb": {"checked": False, "available": False, "reported_times": None, "abuse_confidence_score": None},
        "spamhaus": {"listed": False, "lists": [], "error": None},
        "overall_risk": "low",
        "error": None,
    }


def _dummy_exposure_summary():
    return {
        "public_exposure": False,
        "highest_severity": "low",
        "highest_score": 0,
        "highest_finding": "No significant exposure.",
        "highest_port": None,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
    }


def _dummy_attack_paths():
    return {
        "nodes": [],
        "edges": [],
        "paths": [],
        "summary": "No attack paths identified.",
        "highest_severity": "low",
    }


def _dummy_misconfiguration_summary():
    return {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "categories": []}


def _dummy_attack_surface():
    return {"level": "LOW", "score": 5, "publicly_exposed_services": [], "factors": [], "summary": "Low attack surface."}


# ---------------------------------------------------------------------------
# Helpers to build a fully-patched scan_ports call
# ---------------------------------------------------------------------------

def _common_patches(
    open_ports,
    *,
    cve_delay: float = 0.0,
    misconfig_delay: float = 0.0,
    screenshot_delay: float = 0.0,
    threat_intel_delay: float = 0.0,
    ssl_result=None,
):
    """
    Return a dict of patch targets → mock objects suitable for use with
    unittest.mock.patch.  IO-heavy steps are replaced with asyncio.sleep
    stand-ins so we can measure wall-clock parallelism.
    """
    async def _slow_cves(version_strings, db_session=None):
        await asyncio.sleep(cve_delay)
        return {}

    async def _slow_misconfig(target, ports, timeout, ssl_cache=None):
        await asyncio.sleep(misconfig_delay)
        return _dummy_misconfiguration_summary()

    async def _slow_screenshot(target, ports):
        await asyncio.sleep(screenshot_delay)

    async def _slow_threat_intel(ip):
        await asyncio.sleep(threat_intel_delay)
        return _dummy_threat_intel()

    async def _fake_ssl_audit(host, port):
        return ssl_result if ssl_result is not None else _dummy_ssl_result(port)

    return {
        "cybersec.core.tools.port_scanner.detect_cves_batch": AsyncMock(side_effect=_slow_cves),
        "cybersec.core.tools.port_scanner.detect_misconfigurations": AsyncMock(side_effect=_slow_misconfig),
        "cybersec.core.tools.port_scanner.capture_web_port_screenshots": AsyncMock(side_effect=_slow_screenshot),
        "cybersec.core.tools.port_scanner.check_threat_intelligence": AsyncMock(side_effect=_slow_threat_intel),
        "cybersec.core.tools.port_scanner.ssl_audit": AsyncMock(side_effect=_fake_ssl_audit),
    }


# ---------------------------------------------------------------------------
# Test 1: Parallelization – scan_ports
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_scan_ports_parallel_analysis():
    """
    The four independent analysis steps (detect_cves_batch,
    detect_misconfigurations, capture_web_port_screenshots,
    check_threat_intelligence) must run concurrently.

    With each step sleeping N seconds the total wall-clock time should be
    close to max(N) rather than sum(N).
    """
    DELAY = 0.15  # seconds — enough to be measurable without slowing CI

    open_port = _make_open_port(80, version="Apache/2.4.51")

    patches = _common_patches(
        [open_port],
        cve_delay=DELAY,
        misconfig_delay=DELAY,
        screenshot_delay=DELAY,
        threat_intel_delay=DELAY,
    )

    async def _fake_check_port(ip, port, timeout, hostname=None):
        if port == 80:
            return open_port
        return None

    async def _fake_getaddrinfo(*args, **kwargs):
        return [(None, None, None, None, ("1.2.3.4", 0))]

    with (
        patch("cybersec.core.tools.port_scanner.check_port", side_effect=_fake_check_port),
        patch("asyncio.get_running_loop") as mock_loop,
        patch("cybersec.core.tools.port_scanner.detect_cves_batch", patches["cybersec.core.tools.port_scanner.detect_cves_batch"]),
        patch("cybersec.core.tools.port_scanner.detect_misconfigurations", patches["cybersec.core.tools.port_scanner.detect_misconfigurations"]),
        patch("cybersec.core.tools.port_scanner.capture_web_port_screenshots", patches["cybersec.core.tools.port_scanner.capture_web_port_screenshots"]),
        patch("cybersec.core.tools.port_scanner.check_threat_intelligence", patches["cybersec.core.tools.port_scanner.check_threat_intelligence"]),
        patch("cybersec.core.tools.port_scanner.ssl_audit", patches["cybersec.core.tools.port_scanner.ssl_audit"]),
        patch("cybersec.core.tools.port_scanner.add_ai_recommendations", AsyncMock(return_value=None)),
        patch("cybersec.core.tools.port_scanner.calculate_security_score", AsyncMock(return_value=(80, []))),
        patch("cybersec.core.tools.port_scanner.calculate_exposure_severity", MagicMock(return_value=_dummy_exposure_summary())),
        patch("cybersec.core.tools.port_scanner.build_attack_path_visualization", MagicMock(return_value=_dummy_attack_paths())),
        patch("cybersec.core.tools.port_scanner.build_attack_simulation_recommendations", MagicMock(return_value=[])),
        patch("cybersec.core.tools.port_scanner.calculate_attack_surface", MagicMock(return_value=_dummy_attack_surface())),
        patch("cybersec.core.tools.port_scanner.add_mitre_attack_mapping", MagicMock()),
        patch("cybersec.core.tools.port_scanner.add_exploit_availability", MagicMock()),
        patch("cybersec.core.tools.port_scanner.add_service_fingerprints", MagicMock()),
    ):
        loop_mock = MagicMock()
        loop_mock.getaddrinfo = AsyncMock(return_value=[(None, None, None, None, ("1.2.3.4", 0))])
        mock_loop.return_value = loop_mock

        t0 = time.perf_counter()
        result = await scan_ports("example.com", ports=[80], timeout=2.0)
        elapsed = time.perf_counter() - t0

    # Should finish in roughly 1×DELAY, not 4×DELAY.
    # Allow a generous 3× budget for overhead while still catching sequential execution.
    assert elapsed < DELAY * 3, (
        f"Expected parallel execution (~{DELAY:.2f}s), got {elapsed:.3f}s "
        f"(sequential would be ~{DELAY * 4:.2f}s)"
    )
    assert result.error is None


# ---------------------------------------------------------------------------
# Test 2: Parallelization – stream_port_scan_events
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_stream_port_scan_events_parallel_analysis():
    """
    The same three independent steps inside stream_port_scan_events must also
    run concurrently.
    """
    DELAY = 0.15

    open_port = _make_open_port(80, version="nginx/1.21.0")

    patches = _common_patches(
        [open_port],
        cve_delay=DELAY,
        misconfig_delay=DELAY,
        threat_intel_delay=DELAY,
    )

    async def _fake_check_port(ip, port, timeout, hostname=None):
        if port == 80:
            return open_port
        return None

    with (
        patch("cybersec.core.tools.port_scanner.check_port", side_effect=_fake_check_port),
        patch("asyncio.get_running_loop") as mock_loop,
        patch("cybersec.core.tools.port_scanner.detect_cves_batch", patches["cybersec.core.tools.port_scanner.detect_cves_batch"]),
        patch("cybersec.core.tools.port_scanner.detect_misconfigurations", patches["cybersec.core.tools.port_scanner.detect_misconfigurations"]),
        patch("cybersec.core.tools.port_scanner.capture_web_port_screenshots", patches["cybersec.core.tools.port_scanner.capture_web_port_screenshots"]),
        patch("cybersec.core.tools.port_scanner.check_threat_intelligence", patches["cybersec.core.tools.port_scanner.check_threat_intelligence"]),
        patch("cybersec.core.tools.port_scanner.ssl_audit", patches["cybersec.core.tools.port_scanner.ssl_audit"]),
        patch("cybersec.core.tools.port_scanner.add_ai_recommendations", AsyncMock(return_value=None)),
        patch("cybersec.core.tools.port_scanner.calculate_security_score", AsyncMock(return_value=(80, []))),
        patch("cybersec.core.tools.port_scanner.calculate_exposure_severity", MagicMock(return_value=_dummy_exposure_summary())),
        patch("cybersec.core.tools.port_scanner.build_attack_path_visualization", MagicMock(return_value=_dummy_attack_paths())),
        patch("cybersec.core.tools.port_scanner.build_attack_simulation_recommendations", MagicMock(return_value=[])),
        patch("cybersec.core.tools.port_scanner.calculate_attack_surface", MagicMock(return_value=_dummy_attack_surface())),
        patch("cybersec.core.tools.port_scanner.add_mitre_attack_mapping", MagicMock()),
        patch("cybersec.core.tools.port_scanner.add_exploit_availability", MagicMock()),
        patch("cybersec.core.tools.port_scanner.add_service_fingerprints", MagicMock()),
    ):
        loop_mock = MagicMock()
        loop_mock.getaddrinfo = AsyncMock(return_value=[(None, None, None, None, ("1.2.3.4", 0))])
        mock_loop.return_value = loop_mock

        t0 = time.perf_counter()
        events = []
        async for event in stream_port_scan_events("example.com", ports=[80], timeout=2.0):
            events.append(event)
        elapsed = time.perf_counter() - t0

    assert elapsed < DELAY * 3, (
        f"Expected parallel execution (~{DELAY:.2f}s), got {elapsed:.3f}s "
        f"(sequential would be ~{DELAY * 4:.2f}s)"
    )
    event_types = [e["type"] for e in events]
    assert "done" in event_types


# ---------------------------------------------------------------------------
# Test 3: ssl_audit called exactly once per HTTPS port – scan_ports
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_ssl_audit_called_once_per_https_port_scan_ports():
    """
    When port 443 is open, ssl_audit must be called exactly once for port 443
    regardless of how many downstream functions (detect_misconfigurations,
    calculate_security_score) would otherwise call it independently.
    """
    https_port = _make_open_port(443, service="https")
    ssl_result = _dummy_ssl_result(443)
    ssl_mock = AsyncMock(return_value=ssl_result)

    async def _fake_check_port(ip, port, timeout, hostname=None):
        if port == 443:
            return https_port
        return None

    # detect_misconfigurations and calculate_security_score must receive the
    # cache and NOT call ssl_audit themselves — we verify via ssl_mock.call_count.
    async def _real_detect_misconfigs(target, ports, timeout, ssl_cache=None):
        # Simulate what the real function does: use the cache if provided.
        # We should NOT call ssl_audit here because ssl_cache is provided.
        assert ssl_cache is not None, "ssl_cache should be passed to detect_misconfigurations"
        return _dummy_misconfiguration_summary()

    async def _real_calculate_score(target, ports, ssl_cache=None):
        assert ssl_cache is not None, "ssl_cache should be passed to calculate_security_score"
        return (85, [])

    with (
        patch("cybersec.core.tools.port_scanner.check_port", side_effect=_fake_check_port),
        patch("asyncio.get_running_loop") as mock_loop,
        patch("cybersec.core.tools.port_scanner.ssl_audit", ssl_mock),
        patch("cybersec.core.tools.port_scanner.detect_cves_batch", AsyncMock(return_value={})),
        patch("cybersec.core.tools.port_scanner.detect_misconfigurations", AsyncMock(side_effect=_real_detect_misconfigs)),
        patch("cybersec.core.tools.port_scanner.capture_web_port_screenshots", AsyncMock(return_value=None)),
        patch("cybersec.core.tools.port_scanner.check_threat_intelligence", AsyncMock(return_value=_dummy_threat_intel())),
        patch("cybersec.core.tools.port_scanner.calculate_security_score", AsyncMock(side_effect=_real_calculate_score)),
        patch("cybersec.core.tools.port_scanner.add_ai_recommendations", AsyncMock(return_value=None)),
        patch("cybersec.core.tools.port_scanner.calculate_exposure_severity", MagicMock(return_value=_dummy_exposure_summary())),
        patch("cybersec.core.tools.port_scanner.build_attack_path_visualization", MagicMock(return_value=_dummy_attack_paths())),
        patch("cybersec.core.tools.port_scanner.build_attack_simulation_recommendations", MagicMock(return_value=[])),
        patch("cybersec.core.tools.port_scanner.calculate_attack_surface", MagicMock(return_value=_dummy_attack_surface())),
        patch("cybersec.core.tools.port_scanner.add_mitre_attack_mapping", MagicMock()),
        patch("cybersec.core.tools.port_scanner.add_exploit_availability", MagicMock()),
        patch("cybersec.core.tools.port_scanner.add_service_fingerprints", MagicMock()),
    ):
        loop_mock = MagicMock()
        loop_mock.getaddrinfo = AsyncMock(return_value=[(None, None, None, None, ("1.2.3.4", 0))])
        mock_loop.return_value = loop_mock

        result = await scan_ports("example.com", ports=[443], timeout=2.0)

    assert result.error is None
    # ssl_audit must have been called exactly once for port 443
    assert ssl_mock.call_count == 1, (
        f"ssl_audit should be called exactly once for port 443, got {ssl_mock.call_count} call(s)"
    )
    assert ssl_mock.call_args == call("example.com", 443)


# ---------------------------------------------------------------------------
# Test 4: ssl_audit called once per HTTPS port – stream_port_scan_events
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_ssl_audit_called_once_per_https_port_stream():
    """
    Same ssl_audit deduplication guarantee for stream_port_scan_events.
    """
    https_port = _make_open_port(443, service="https")
    ssl_result = _dummy_ssl_result(443)
    ssl_mock = AsyncMock(return_value=ssl_result)

    async def _fake_check_port(ip, port, timeout, hostname=None):
        if port == 443:
            return https_port
        return None

    async def _real_detect_misconfigs(target, ports, timeout, ssl_cache=None):
        assert ssl_cache is not None, "ssl_cache should be passed to detect_misconfigurations"
        return _dummy_misconfiguration_summary()

    async def _real_calculate_score(target, ports, ssl_cache=None):
        assert ssl_cache is not None, "ssl_cache should be passed to calculate_security_score"
        return (85, [])

    with (
        patch("cybersec.core.tools.port_scanner.check_port", side_effect=_fake_check_port),
        patch("asyncio.get_running_loop") as mock_loop,
        patch("cybersec.core.tools.port_scanner.ssl_audit", ssl_mock),
        patch("cybersec.core.tools.port_scanner.detect_cves_batch", AsyncMock(return_value={})),
        patch("cybersec.core.tools.port_scanner.detect_misconfigurations", AsyncMock(side_effect=_real_detect_misconfigs)),
        patch("cybersec.core.tools.port_scanner.capture_web_port_screenshots", AsyncMock(return_value=None)),
        patch("cybersec.core.tools.port_scanner.check_threat_intelligence", AsyncMock(return_value=_dummy_threat_intel())),
        patch("cybersec.core.tools.port_scanner.calculate_security_score", AsyncMock(side_effect=_real_calculate_score)),
        patch("cybersec.core.tools.port_scanner.add_ai_recommendations", AsyncMock(return_value=None)),
        patch("cybersec.core.tools.port_scanner.calculate_exposure_severity", MagicMock(return_value=_dummy_exposure_summary())),
        patch("cybersec.core.tools.port_scanner.build_attack_path_visualization", MagicMock(return_value=_dummy_attack_paths())),
        patch("cybersec.core.tools.port_scanner.build_attack_simulation_recommendations", MagicMock(return_value=[])),
        patch("cybersec.core.tools.port_scanner.calculate_attack_surface", MagicMock(return_value=_dummy_attack_surface())),
        patch("cybersec.core.tools.port_scanner.add_mitre_attack_mapping", MagicMock()),
        patch("cybersec.core.tools.port_scanner.add_exploit_availability", MagicMock()),
        patch("cybersec.core.tools.port_scanner.add_service_fingerprints", MagicMock()),
    ):
        loop_mock = MagicMock()
        loop_mock.getaddrinfo = AsyncMock(return_value=[(None, None, None, None, ("1.2.3.4", 0))])
        mock_loop.return_value = loop_mock

        events = []
        async for event in stream_port_scan_events("example.com", ports=[443], timeout=2.0):
            events.append(event)

    assert any(e["type"] == "done" for e in events)
    assert ssl_mock.call_count == 1, (
        f"ssl_audit should be called exactly once for port 443, got {ssl_mock.call_count} call(s)"
    )
    assert ssl_mock.call_args == call("example.com", 443)


# ---------------------------------------------------------------------------
# Test 5: Multiple HTTPS ports – each audited exactly once
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_ssl_audit_called_once_per_https_port_multiple_ports():
    """
    When both 443 and 8443 are open, ssl_audit is called exactly once per port
    (total 2 calls), with no duplicates across the two consumers.
    """
    port_443 = _make_open_port(443, service="https")
    port_8443 = _make_open_port(8443, service="https-alt")

    ssl_mock = AsyncMock(side_effect=lambda host, port: _dummy_ssl_result(port))

    async def _fake_check_port(ip, port, timeout, hostname=None):
        if port == 443:
            return port_443
        if port == 8443:
            return port_8443
        return None

    with (
        patch("cybersec.core.tools.port_scanner.check_port", side_effect=_fake_check_port),
        patch("asyncio.get_running_loop") as mock_loop,
        patch("cybersec.core.tools.port_scanner.ssl_audit", ssl_mock),
        patch("cybersec.core.tools.port_scanner.detect_cves_batch", AsyncMock(return_value={})),
        patch("cybersec.core.tools.port_scanner.detect_misconfigurations", AsyncMock(return_value=_dummy_misconfiguration_summary())),
        patch("cybersec.core.tools.port_scanner.capture_web_port_screenshots", AsyncMock(return_value=None)),
        patch("cybersec.core.tools.port_scanner.check_threat_intelligence", AsyncMock(return_value=_dummy_threat_intel())),
        patch("cybersec.core.tools.port_scanner.calculate_security_score", AsyncMock(return_value=(75, []))),
        patch("cybersec.core.tools.port_scanner.add_ai_recommendations", AsyncMock(return_value=None)),
        patch("cybersec.core.tools.port_scanner.calculate_exposure_severity", MagicMock(return_value=_dummy_exposure_summary())),
        patch("cybersec.core.tools.port_scanner.build_attack_path_visualization", MagicMock(return_value=_dummy_attack_paths())),
        patch("cybersec.core.tools.port_scanner.build_attack_simulation_recommendations", MagicMock(return_value=[])),
        patch("cybersec.core.tools.port_scanner.calculate_attack_surface", MagicMock(return_value=_dummy_attack_surface())),
        patch("cybersec.core.tools.port_scanner.add_mitre_attack_mapping", MagicMock()),
        patch("cybersec.core.tools.port_scanner.add_exploit_availability", MagicMock()),
        patch("cybersec.core.tools.port_scanner.add_service_fingerprints", MagicMock()),
    ):
        loop_mock = MagicMock()
        loop_mock.getaddrinfo = AsyncMock(return_value=[(None, None, None, None, ("1.2.3.4", 0))])
        mock_loop.return_value = loop_mock

        result = await scan_ports("example.com", ports=[443, 8443], timeout=2.0)

    assert result.error is None
    audited_ports = {c.args[1] for c in ssl_mock.call_args_list}
    assert audited_ports == {443, 8443}, f"Expected exactly {{443, 8443}} audited, got {audited_ports}"
    assert ssl_mock.call_count == 2, (
        f"Expected 2 ssl_audit calls (one per HTTPS port), got {ssl_mock.call_count}"
    )


# ---------------------------------------------------------------------------
# Shared helper for flag tests
# ---------------------------------------------------------------------------

def _base_patches_for_flags(open_port):
    """Minimal patches to make scan_ports() complete without real network I/O."""
    async def _fake_check_port(ip, port, timeout, hostname=None):
        return open_port if port == open_port.port_number else None

    return {
        "check_port": AsyncMock(side_effect=_fake_check_port),
        "detect_cves_batch": AsyncMock(return_value={}),
        "detect_misconfigurations": AsyncMock(return_value=_dummy_misconfiguration_summary()),
        "capture_web_port_screenshots": AsyncMock(return_value=None),
        "calculate_security_score": AsyncMock(return_value=(80, [])),
        "calculate_exposure_severity": MagicMock(return_value=_dummy_exposure_summary()),
        "build_attack_path_visualization": MagicMock(return_value=_dummy_attack_paths()),
        "build_attack_simulation_recommendations": MagicMock(return_value=[]),
        "calculate_attack_surface": MagicMock(return_value=_dummy_attack_surface()),
        "add_mitre_attack_mapping": MagicMock(),
        "add_exploit_availability": MagicMock(),
        "add_service_fingerprints": MagicMock(),
    }


# ---------------------------------------------------------------------------
# Test 6: include_ai_recommendations=False — groq never called
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_include_ai_recommendations_false():
    """
    When include_ai_recommendations=False the Groq client must never be called,
    recommendations_error must be None, and no port should have a recommendation.
    """
    open_port = _make_open_port(80, service="http", version="Apache/2.4.51")
    patches = _base_patches_for_flags(open_port)

    groq_chat_mock = AsyncMock(return_value='{"recommendations": []}')
    threat_intel_mock = AsyncMock(return_value=_dummy_threat_intel())

    with (
        patch("cybersec.core.tools.port_scanner.check_port", patches["check_port"]),
        patch("asyncio.get_running_loop") as mock_loop,
        patch("cybersec.core.tools.port_scanner.detect_cves_batch", patches["detect_cves_batch"]),
        patch("cybersec.core.tools.port_scanner.detect_misconfigurations", patches["detect_misconfigurations"]),
        patch("cybersec.core.tools.port_scanner.capture_web_port_screenshots", patches["capture_web_port_screenshots"]),
        patch("cybersec.core.tools.port_scanner.check_threat_intelligence", threat_intel_mock),
        patch("cybersec.core.tools.port_scanner.ssl_audit", AsyncMock(side_effect=lambda h, p: _dummy_ssl_result(p))),
        patch("cybersec.core.tools.port_scanner.calculate_security_score", patches["calculate_security_score"]),
        patch("cybersec.core.tools.port_scanner.calculate_exposure_severity", patches["calculate_exposure_severity"]),
        patch("cybersec.core.tools.port_scanner.build_attack_path_visualization", patches["build_attack_path_visualization"]),
        patch("cybersec.core.tools.port_scanner.build_attack_simulation_recommendations", patches["build_attack_simulation_recommendations"]),
        patch("cybersec.core.tools.port_scanner.calculate_attack_surface", patches["calculate_attack_surface"]),
        patch("cybersec.core.tools.port_scanner.add_mitre_attack_mapping", patches["add_mitre_attack_mapping"]),
        patch("cybersec.core.tools.port_scanner.add_exploit_availability", patches["add_exploit_availability"]),
        patch("cybersec.core.tools.port_scanner.add_service_fingerprints", patches["add_service_fingerprints"]),
    ):
        # Patch groq_client inside the module namespace
        groq_mock = MagicMock()
        groq_mock.chat = groq_chat_mock
        with patch.dict("sys.modules", {"cybersec.integrations.ai.groq_client": MagicMock(groq_client=groq_mock)}):
            loop_mock = MagicMock()
            loop_mock.getaddrinfo = AsyncMock(return_value=[(None, None, None, None, ("1.2.3.4", 0))])
            mock_loop.return_value = loop_mock

            result = await scan_ports(
                "example.com",
                ports=[80],
                timeout=2.0,
                include_ai_recommendations=False,
            )

    groq_chat_mock.assert_not_called()
    assert result.recommendations_error is None
    for port in result.open_ports:
        assert port.recommendation is None


# ---------------------------------------------------------------------------
# Test 7: include_threat_intel=False — AbuseIPDB/Spamhaus never called
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_include_threat_intel_false():
    """
    When include_threat_intel=False neither AbuseIPDB nor Spamhaus must be
    contacted and threat_intelligence.reputation must be 'Not checked'.
    """
    open_port = _make_open_port(80, service="http")
    patches = _base_patches_for_flags(open_port)

    abuseipdb_mock = AsyncMock()
    spamhaus_mock = AsyncMock()

    with (
        patch("cybersec.core.tools.port_scanner.check_port", patches["check_port"]),
        patch("asyncio.get_running_loop") as mock_loop,
        patch("cybersec.core.tools.port_scanner.detect_cves_batch", patches["detect_cves_batch"]),
        patch("cybersec.core.tools.port_scanner.detect_misconfigurations", patches["detect_misconfigurations"]),
        patch("cybersec.core.tools.port_scanner.capture_web_port_screenshots", patches["capture_web_port_screenshots"]),
        patch("cybersec.core.tools.port_scanner._abuseipdb_check", abuseipdb_mock),
        patch("cybersec.core.tools.port_scanner._spamhaus_check", spamhaus_mock),
        patch("cybersec.core.tools.port_scanner.ssl_audit", AsyncMock(side_effect=lambda h, p: _dummy_ssl_result(p))),
        patch("cybersec.core.tools.port_scanner.add_ai_recommendations", AsyncMock(return_value=None)),
        patch("cybersec.core.tools.port_scanner.calculate_security_score", patches["calculate_security_score"]),
        patch("cybersec.core.tools.port_scanner.calculate_exposure_severity", patches["calculate_exposure_severity"]),
        patch("cybersec.core.tools.port_scanner.build_attack_path_visualization", patches["build_attack_path_visualization"]),
        patch("cybersec.core.tools.port_scanner.build_attack_simulation_recommendations", patches["build_attack_simulation_recommendations"]),
        patch("cybersec.core.tools.port_scanner.calculate_attack_surface", patches["calculate_attack_surface"]),
        patch("cybersec.core.tools.port_scanner.add_mitre_attack_mapping", patches["add_mitre_attack_mapping"]),
        patch("cybersec.core.tools.port_scanner.add_exploit_availability", patches["add_exploit_availability"]),
        patch("cybersec.core.tools.port_scanner.add_service_fingerprints", patches["add_service_fingerprints"]),
    ):
        loop_mock = MagicMock()
        loop_mock.getaddrinfo = AsyncMock(return_value=[(None, None, None, None, ("1.2.3.4", 0))])
        mock_loop.return_value = loop_mock

        result = await scan_ports(
            "example.com",
            ports=[80],
            timeout=2.0,
            include_threat_intel=False,
        )

    abuseipdb_mock.assert_not_called()
    spamhaus_mock.assert_not_called()
    assert result.threat_intelligence.get("reputation") == "Not checked"


# ---------------------------------------------------------------------------
# Test 8: both flags True (default) — existing behavior unchanged
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_both_flags_true_default_behavior():
    """
    With both flags True (the default), add_ai_recommendations and
    check_threat_intelligence are still called as normal.
    """
    open_port = _make_open_port(80, service="http", version="nginx/1.21.0")
    patches = _base_patches_for_flags(open_port)

    ai_mock = AsyncMock(return_value=None)
    threat_intel_mock = AsyncMock(return_value=_dummy_threat_intel())

    with (
        patch("cybersec.core.tools.port_scanner.check_port", patches["check_port"]),
        patch("asyncio.get_running_loop") as mock_loop,
        patch("cybersec.core.tools.port_scanner.detect_cves_batch", patches["detect_cves_batch"]),
        patch("cybersec.core.tools.port_scanner.detect_misconfigurations", patches["detect_misconfigurations"]),
        patch("cybersec.core.tools.port_scanner.capture_web_port_screenshots", patches["capture_web_port_screenshots"]),
        patch("cybersec.core.tools.port_scanner.check_threat_intelligence", threat_intel_mock),
        patch("cybersec.core.tools.port_scanner.add_ai_recommendations", ai_mock),
        patch("cybersec.core.tools.port_scanner.ssl_audit", AsyncMock(side_effect=lambda h, p: _dummy_ssl_result(p))),
        patch("cybersec.core.tools.port_scanner.calculate_security_score", patches["calculate_security_score"]),
        patch("cybersec.core.tools.port_scanner.calculate_exposure_severity", patches["calculate_exposure_severity"]),
        patch("cybersec.core.tools.port_scanner.build_attack_path_visualization", patches["build_attack_path_visualization"]),
        patch("cybersec.core.tools.port_scanner.build_attack_simulation_recommendations", patches["build_attack_simulation_recommendations"]),
        patch("cybersec.core.tools.port_scanner.calculate_attack_surface", patches["calculate_attack_surface"]),
        patch("cybersec.core.tools.port_scanner.add_mitre_attack_mapping", patches["add_mitre_attack_mapping"]),
        patch("cybersec.core.tools.port_scanner.add_exploit_availability", patches["add_exploit_availability"]),
        patch("cybersec.core.tools.port_scanner.add_service_fingerprints", patches["add_service_fingerprints"]),
    ):
        loop_mock = MagicMock()
        loop_mock.getaddrinfo = AsyncMock(return_value=[(None, None, None, None, ("1.2.3.4", 0))])
        mock_loop.return_value = loop_mock

        result = await scan_ports(
            "example.com",
            ports=[80],
            timeout=2.0,
            # defaults: include_ai_recommendations=True, include_threat_intel=True
        )

    ai_mock.assert_called_once()
    threat_intel_mock.assert_called_once()
    assert result.error is None


# ---------------------------------------------------------------------------
# Test 9: both flags False — completes successfully, neither service called
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_both_flags_false_neither_service_called():
    """
    With both flags False, scan_ports() returns successfully without calling
    add_ai_recommendations or check_threat_intelligence at all.
    """
    open_port = _make_open_port(80, service="http")
    patches = _base_patches_for_flags(open_port)

    ai_mock = AsyncMock(return_value=None)
    threat_intel_mock = AsyncMock(return_value=_dummy_threat_intel())

    with (
        patch("cybersec.core.tools.port_scanner.check_port", patches["check_port"]),
        patch("asyncio.get_running_loop") as mock_loop,
        patch("cybersec.core.tools.port_scanner.detect_cves_batch", patches["detect_cves_batch"]),
        patch("cybersec.core.tools.port_scanner.detect_misconfigurations", patches["detect_misconfigurations"]),
        patch("cybersec.core.tools.port_scanner.capture_web_port_screenshots", patches["capture_web_port_screenshots"]),
        patch("cybersec.core.tools.port_scanner.check_threat_intelligence", threat_intel_mock),
        patch("cybersec.core.tools.port_scanner.add_ai_recommendations", ai_mock),
        patch("cybersec.core.tools.port_scanner.ssl_audit", AsyncMock(side_effect=lambda h, p: _dummy_ssl_result(p))),
        patch("cybersec.core.tools.port_scanner.calculate_security_score", patches["calculate_security_score"]),
        patch("cybersec.core.tools.port_scanner.calculate_exposure_severity", patches["calculate_exposure_severity"]),
        patch("cybersec.core.tools.port_scanner.build_attack_path_visualization", patches["build_attack_path_visualization"]),
        patch("cybersec.core.tools.port_scanner.build_attack_simulation_recommendations", patches["build_attack_simulation_recommendations"]),
        patch("cybersec.core.tools.port_scanner.calculate_attack_surface", patches["calculate_attack_surface"]),
        patch("cybersec.core.tools.port_scanner.add_mitre_attack_mapping", patches["add_mitre_attack_mapping"]),
        patch("cybersec.core.tools.port_scanner.add_exploit_availability", patches["add_exploit_availability"]),
        patch("cybersec.core.tools.port_scanner.add_service_fingerprints", patches["add_service_fingerprints"]),
    ):
        loop_mock = MagicMock()
        loop_mock.getaddrinfo = AsyncMock(return_value=[(None, None, None, None, ("1.2.3.4", 0))])
        mock_loop.return_value = loop_mock

        result = await scan_ports(
            "example.com",
            ports=[80],
            timeout=2.0,
            include_ai_recommendations=False,
            include_threat_intel=False,
        )

    ai_mock.assert_not_called()
    threat_intel_mock.assert_not_called()
    assert result.error is None
    assert result.recommendations_error is None
    assert result.threat_intelligence.get("reputation") == "Not checked"
