"""
Tests for cybersec/core/tools/cve_detect.py

Coverage:
  - detect_cves_batch delegates to NVDClient.lookup_cves_for_service.
  - _enforce_rate_limit is awaited once per version-string lookup (proves the
    rate-limit path is exercised for every item in the batch, not bypassed).
  - The adapter correctly maps nvd_client.CVEResult → cve_detect.CVEResult /
    cve_detect.CVE with the right severity counts.
  - detect_cves_batch with a db_session passes it through to NVDClient.
"""
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch, call
from dataclasses import dataclass, field
from typing import Optional, List

import pytest


# ---------------------------------------------------------------------------
# Helpers — minimal stub for nvd_client.CVEResult
# ---------------------------------------------------------------------------

def _make_nvd_result(cve_id: str, score: float, severity: str) -> MagicMock:
    r = MagicMock()
    r.cve_id = cve_id
    r.description = f"desc of {cve_id}"
    r.cvss_v3_score = score
    r.cvss_v2_score = None
    r.cvss_v3_severity = severity
    r.cvss_v3_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    r.published = "2024-01-15T00:00:00.000"
    return r


# ---------------------------------------------------------------------------
# Test 1: rate-limit is enforced once per lookup (per version string)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_rate_limit_enforced_once_per_version_string():
    """
    With 5 version strings, _enforce_rate_limit must be awaited exactly 5 times
    (once per NVDClient._make_request → one per lookup_cves_for_service call).
    We use zero rate-limit delay and stub the HTTP layer so the test is instant.
    Call count on _enforce_rate_limit proves rate limiting is exercised, not
    bypassed, for every item in the batch.
    """
    import importlib.util
    import pathlib
    import sys
    import cybersec.core.tools.cve_detect as cve_mod

    # Load nvd_client.py directly, bypassing security/__init__.py which has a
    # broken import of cybersec.core.scanner.analysis in this environment.
    nvd_path = (
        pathlib.Path(__file__).parents[3]
        / "cybersec" / "core" / "security" / "nvd_client.py"
    )
    spec = importlib.util.spec_from_file_location("_nvd_client_rl", nvd_path)
    nvd_mod = importlib.util.module_from_spec(spec)
    # NVDCveCache is referenced only inside NVDCacheManager methods, not at
    # class-definition time, so a simple MagicMock stub is sufficient here.
    if "cybersec.database.models" not in sys.modules:
        import types
        stub = types.ModuleType("cybersec.database.models")
        stub.NVDCveCache = MagicMock
        sys.modules["cybersec.database.models"] = stub
    spec.loader.exec_module(nvd_mod)
    NVDClient = nvd_mod.NVDClient

    # Create a client with 0s rate-limit delay so there's no real sleeping.
    client = NVDClient(rate_limit_delay=0.0)

    # Spy on _enforce_rate_limit: count calls but still execute the real logic.
    enforce_calls = 0
    _orig_enforce = client._enforce_rate_limit

    async def counting_enforce():
        nonlocal enforce_calls
        enforce_calls += 1
        await _orig_enforce()

    client._enforce_rate_limit = counting_enforce

    # We need the real _make_request to execute (so it calls _enforce_rate_limit)
    # but without making real HTTP calls.  Patch httpx.AsyncClient so it returns
    # a fake 200 response with empty vulnerabilities.
    from unittest.mock import patch as _patch, AsyncMock as _AsyncMock

    _fake_resp = MagicMock()
    _fake_resp.status_code = 200
    _fake_resp.json.return_value = {"vulnerabilities": []}
    _fake_resp.raise_for_status = MagicMock()

    _fake_http = MagicMock()
    _fake_http.__aenter__ = _AsyncMock(
        return_value=MagicMock(get=_AsyncMock(return_value=_fake_resp))
    )
    _fake_http.__aexit__ = _AsyncMock(return_value=False)

    # Inject as the module-level singleton — _get_nvd_client() returns it
    # because _nvd_client is non-None.
    original_client = cve_mod._nvd_client
    cve_mod._nvd_client = client

    version_strings = [
        "Apache/2.4.51",
        "nginx/1.21.0",
        "OpenSSH_8.2p1",
        "MySQL/5.7.33",
        "vsftpd/3.0.3",
    ]

    with _patch("httpx.AsyncClient", return_value=_fake_http):
        try:
            await cve_mod.detect_cves_batch(version_strings)
        finally:
            cve_mod._nvd_client = original_client

    # Each parseable version string → one lookup_cves_for_service call →
    # one search_cves_by_keyword call → one _make_request call →
    # one _enforce_rate_limit call.
    assert enforce_calls == 5, (
        f"Expected _enforce_rate_limit to be called once per version string "
        f"(5 times), but it was called {enforce_calls} times."
    )


# ---------------------------------------------------------------------------
# Test 2: adapter maps NVD severity → cve_detect CVE/CVEResult correctly
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_adapter_maps_severity_counts():
    """
    _nvd_results_to_cve_result should produce correct critical/high/medium/low
    counts and populate CVE fields from nvd_client.CVEResult attributes.
    """
    from cybersec.core.tools.cve_detect import _nvd_results_to_cve_result, CVE, CVEResult

    nvd_cves = [
        _make_nvd_result("CVE-2024-0001", 9.8, "CRITICAL"),
        _make_nvd_result("CVE-2024-0002", 7.5, "HIGH"),
        _make_nvd_result("CVE-2024-0003", 5.3, "MEDIUM"),
        _make_nvd_result("CVE-2024-0004", 3.1, "LOW"),
        _make_nvd_result("CVE-2024-0005", 9.1, "CRITICAL"),
    ]

    result = _nvd_results_to_cve_result("apache", "2.4.51", nvd_cves)

    assert isinstance(result, CVEResult)
    assert result.service_name == "apache"
    assert result.version == "2.4.51"
    assert result.total_count == 5
    assert result.critical_count == 2
    assert result.high_count == 1
    assert result.medium_count == 1
    assert result.low_count == 1

    cve_0 = result.cves[0]
    assert isinstance(cve_0, CVE)
    assert cve_0.cve_id == "CVE-2024-0001"
    assert cve_0.severity == "CRITICAL"
    assert cve_0.cvss_score == 9.8
    assert cve_0.url == "https://nvd.nist.gov/vuln/detail/CVE-2024-0001"


# ---------------------------------------------------------------------------
# Test 3: db_session is threaded through to lookup_cves_for_service
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_db_session_passed_to_nvd_client():
    """
    detect_cves_batch(version_strings, db_session=mock_db) must forward
    db_session to NVDClient.lookup_cves_for_service.
    """
    import importlib.util
    import pathlib
    import sys
    import cybersec.core.tools.cve_detect as cve_mod

    nvd_path = pathlib.Path(__file__).parents[3] / "cybersec" / "core" / "security" / "nvd_client.py"
    spec = importlib.util.spec_from_file_location("_nvd_client_direct2", nvd_path)
    nvd_mod = importlib.util.module_from_spec(spec)
    if "cybersec.database.models" not in sys.modules:
        import types
        stub = types.ModuleType("cybersec.database.models")
        stub.NVDCveCache = MagicMock
        sys.modules.setdefault("cybersec.database.models", stub)
    spec.loader.exec_module(nvd_mod)
    NVDClient = nvd_mod.NVDClient

    mock_db = MagicMock()
    captured_sessions = []

    async def fake_lookup(service, version, db_session=None):
        captured_sessions.append(db_session)
        return []

    client = NVDClient(rate_limit_delay=0.0)
    client.lookup_cves_for_service = fake_lookup

    original_client = cve_mod._nvd_client
    cve_mod._nvd_client = client

    try:
        await cve_mod.detect_cves_batch(["Apache/2.4.51"], db_session=mock_db)
    finally:
        cve_mod._nvd_client = original_client

    assert len(captured_sessions) == 1
    assert captured_sessions[0] is mock_db, (
        "db_session was not forwarded to NVDClient.lookup_cves_for_service"
    )


# ---------------------------------------------------------------------------
# Test 4: unparseable version strings are silently skipped
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_unparseable_versions_skipped():
    """
    Version strings that parse_version_string cannot decode must be absent from
    the output dict without raising an exception.
    """
    import importlib.util
    import pathlib
    import sys
    from cybersec.core.tools.cve_detect import detect_cves_batch
    import cybersec.core.tools.cve_detect as cve_mod

    nvd_path = pathlib.Path(__file__).parents[3] / "cybersec" / "core" / "security" / "nvd_client.py"
    spec = importlib.util.spec_from_file_location("_nvd_client_direct3", nvd_path)
    nvd_mod = importlib.util.module_from_spec(spec)
    if "cybersec.database.models" not in sys.modules:
        import types
        stub = types.ModuleType("cybersec.database.models")
        stub.NVDCveCache = MagicMock
        sys.modules.setdefault("cybersec.database.models", stub)
    spec.loader.exec_module(nvd_mod)
    NVDClient = nvd_mod.NVDClient

    client = NVDClient(rate_limit_delay=0.0)

    async def fake_lookup(service, version, db_session=None):
        return []

    client.lookup_cves_for_service = fake_lookup

    original_client = cve_mod._nvd_client
    cve_mod._nvd_client = client

    try:
        result = await detect_cves_batch([
            "Apache/2.4.51",   # parseable
            "????",            # unparseable
            "12345",           # unparseable
        ])
    finally:
        cve_mod._nvd_client = original_client

    assert "Apache/2.4.51" in result
    assert "????" not in result
    assert "12345" not in result


# ---------------------------------------------------------------------------
# Test 5: detect_cves_for_version returns None for unknown format
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_detect_cves_for_version_returns_none_for_bad_string():
    from cybersec.core.tools.cve_detect import detect_cves_for_version
    result = await detect_cves_for_version("????")
    assert result is None

    result2 = await detect_cves_for_version("")
    assert result2 is None
