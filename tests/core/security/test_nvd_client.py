"""
Tests for cybersec/core/security/nvd_client.py

Coverage:
  - Regression: EnhancedCVELookup can be instantiated with a mock db_session
    without raising NameError (NVDCveManager → NVDCacheManager bug fix).
  - Cache hit: lookup_cves_for_service calls search_cves_by_keyword exactly
    once across two identical invocations when db_session is provided.
  - Expired cache: a stale entry triggers a fresh NVD call.
  - No-session: db_session=None always calls search_cves_by_keyword and never
    touches cache tables.

nvd_client.py is loaded directly via importlib.util.spec_from_file_location to
avoid executing cybersec/core/security/__init__.py, which imports cve_lookup,
which imports cybersec.core.scanner.analysis (a missing package in the current
test environment).
"""
import importlib.util
import pathlib
import sys
import types
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


def _load_nvd_client():
    """Load nvd_client.py without triggering security/__init__.py."""
    nvd_path = (
        pathlib.Path(__file__).parents[3]
        / "cybersec" / "core" / "security" / "nvd_client.py"
    )
    # Stub cybersec.database.models so module-level imports don't fail.
    if "cybersec.database.models" not in sys.modules:
        stub = types.ModuleType("cybersec.database.models")
        stub.NVDCveCache = MagicMock
        stub.NVDServiceLookupCache = MagicMock
        sys.modules["cybersec.database.models"] = stub
    else:
        stub = sys.modules["cybersec.database.models"]
        if not hasattr(stub, "NVDServiceLookupCache"):
            stub.NVDServiceLookupCache = MagicMock

    spec = importlib.util.spec_from_file_location("_nvd_client_test", nvd_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _make_client(nvd_mod):
    """Build a bare NVDClient with all IO stubs in place."""
    import asyncio
    client = nvd_mod.NVDClient.__new__(nvd_mod.NVDClient)
    client.api_key = None
    client.rate_limit_delay = 6.0
    client._rate_limit_lock = asyncio.Lock()
    client._last_request_time = 0.0
    client.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    client.timeout = 30
    return client


def _make_cve(nvd_mod):
    return nvd_mod.CVEResult(
        cve_id="CVE-2021-41773",
        description="Test",
        published="2021-10-05T00:00:00",
        last_modified="2021-10-06T00:00:00",
        vuln_status="Analyzed",
        cvss_v3_score=7.5,
        cvss_v3_severity="HIGH",
        cvss_v2_score=None,
        cvss_v3_vector=None,
        references=[],
        source="NVD",
    )


# ---------------------------------------------------------------------------
# Existing regression tests
# ---------------------------------------------------------------------------

def test_enhanced_cve_lookup_instantiation_no_name_error():
    nvd = _load_nvd_client()
    mock_db = MagicMock()
    lookup = nvd.EnhancedCVELookup(db_session=mock_db)
    assert lookup.db_session is mock_db
    assert isinstance(lookup.cache_manager, nvd.NVDCacheManager)


def test_enhanced_cve_lookup_no_db_session():
    nvd = _load_nvd_client()
    lookup = nvd.EnhancedCVELookup()
    assert lookup.cache_manager is None


# ---------------------------------------------------------------------------
# Test 1: cache hit — search_cves_by_keyword called exactly once
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_lookup_cves_for_service_cache_hit():
    """Second call with same args is served from cache; NVD is only queried once."""
    nvd = _load_nvd_client()
    cve = _make_cve(nvd)
    keyword_mock = AsyncMock(return_value=[cve])

    stored: list = []

    async def fake_get(service_name, service_version):
        return stored[0] if stored else None

    async def fake_store(service_name, service_version, results):
        stored.append(results)

    mock_cm = MagicMock(spec=nvd.NVDCacheManager)
    mock_cm.get_cached_service_lookup = AsyncMock(side_effect=fake_get)
    mock_cm.cache_service_lookup = AsyncMock(side_effect=fake_store)

    client = _make_client(nvd)
    client.search_cves_by_keyword = keyword_mock

    with patch.object(nvd, "NVDCacheManager", return_value=mock_cm):
        result1 = await client.lookup_cves_for_service("apache", "2.4.49", db_session=MagicMock())
        result2 = await client.lookup_cves_for_service("apache", "2.4.49", db_session=MagicMock())

    assert keyword_mock.call_count == 1, (
        f"search_cves_by_keyword should be called exactly once, got {keyword_mock.call_count}"
    )
    assert len(result1) == len(result2)


# ---------------------------------------------------------------------------
# Test 2: expired cache entry triggers a fresh NVD call
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_lookup_cves_for_service_expired_cache():
    """get_cached_service_lookup always returning None (simulating expiry) → NVD called each time."""
    nvd = _load_nvd_client()
    cve = _make_cve(nvd)
    keyword_mock = AsyncMock(return_value=[cve])

    mock_cm = MagicMock(spec=nvd.NVDCacheManager)
    mock_cm.get_cached_service_lookup = AsyncMock(return_value=None)
    mock_cm.cache_service_lookup = AsyncMock(return_value=None)

    client = _make_client(nvd)
    client.search_cves_by_keyword = keyword_mock

    with patch.object(nvd, "NVDCacheManager", return_value=mock_cm):
        await client.lookup_cves_for_service("apache", "2.4.49", db_session=MagicMock())
        await client.lookup_cves_for_service("apache", "2.4.49", db_session=MagicMock())

    assert keyword_mock.call_count == 2, (
        f"Expired cache should trigger 2 NVD calls, got {keyword_mock.call_count}"
    )


# ---------------------------------------------------------------------------
# Test 3: db_session=None — no cache, always calls NVD
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_lookup_cves_for_service_no_db_session():
    """With db_session=None, NVDCacheManager must never be instantiated."""
    nvd = _load_nvd_client()
    cve = _make_cve(nvd)
    keyword_mock = AsyncMock(return_value=[cve])
    cache_constructor = MagicMock()

    client = _make_client(nvd)
    client.search_cves_by_keyword = keyword_mock

    with patch.object(nvd, "NVDCacheManager", cache_constructor):
        await client.lookup_cves_for_service("apache", "2.4.49", db_session=None)
        await client.lookup_cves_for_service("apache", "2.4.49", db_session=None)

    assert keyword_mock.call_count == 2, (
        f"With db_session=None, NVD should be called every time; got {keyword_mock.call_count}"
    )
    cache_constructor.assert_not_called()
