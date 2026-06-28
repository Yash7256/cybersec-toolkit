"""
Tests for cybersec/core/security/nvd_client.py

Coverage:
  - Regression: EnhancedCVELookup can be instantiated with a mock db_session
    without raising NameError (NVDCveManager → NVDCacheManager bug fix).

nvd_client.py is loaded directly via importlib.util.spec_from_file_location to
avoid executing cybersec/core/security/__init__.py, which imports cve_lookup,
which imports cybersec.core.scanner.analysis (a missing package in the current
test environment).
"""
import importlib.util
import pathlib
import sys
import types
from unittest.mock import MagicMock

import pytest


def _load_nvd_client():
    """Load nvd_client.py without triggering security/__init__.py."""
    nvd_path = (
        pathlib.Path(__file__).parents[3]
        / "cybersec" / "core" / "security" / "nvd_client.py"
    )
    # Stub cybersec.database.models if not already present so the module-level
    # import inside nvd_client.py doesn't fail.
    if "cybersec.database.models" not in sys.modules:
        stub = types.ModuleType("cybersec.database.models")
        stub.NVDCveCache = MagicMock
        sys.modules["cybersec.database.models"] = stub

    spec = importlib.util.spec_from_file_location("_nvd_client_test", nvd_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_enhanced_cve_lookup_instantiation_no_name_error():
    """
    EnhancedCVELookup.__init__ previously referenced NVDCveManager (which does
    not exist); the correct name is NVDCacheManager.  This test proves that
    instantiating with a mock db_session raises no NameError and that
    cache_manager is set to a NVDCacheManager instance.
    """
    nvd = _load_nvd_client()
    EnhancedCVELookup = nvd.EnhancedCVELookup
    NVDCacheManager = nvd.NVDCacheManager

    mock_db = MagicMock()
    # Must not raise NameError
    lookup = EnhancedCVELookup(db_session=mock_db)

    assert lookup.db_session is mock_db
    assert isinstance(lookup.cache_manager, NVDCacheManager)


def test_enhanced_cve_lookup_no_db_session():
    """cache_manager should be None when no db_session is supplied."""
    nvd = _load_nvd_client()
    EnhancedCVELookup = nvd.EnhancedCVELookup

    lookup = EnhancedCVELookup()
    assert lookup.cache_manager is None
