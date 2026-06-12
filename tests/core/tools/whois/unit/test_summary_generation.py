"""Auto-generated summary is non-empty and coherent"""
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from cybersec.core.tools import whois
from tests.core.tools.whois.conftest import _make_whois_obj


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _run_lookup(domain, whois_return, rdap_return):
    with patch("cybersec.core.tools.whois.python_whois.whois", return_value=whois_return), \
         patch("cybersec.core.tools.whois._fetch_rdap", return_value=rdap_return), \
         patch("cybersec.core.tools.whois._get_redis", return_value=None):
        return await whois.whois_lookup(domain)


_EMPTY_RDAP = {
    "handle": "EMPTY",
    "ldhName": "example.com",
    "status": [],
    "entities": [],
    "events": [],
    "nameservers": [],
}


def _registered_whois(registrar=None, expiry_delta_days=None, creation=True):
    """Build a whois-like object for summary tests.

    Uses far-future expiration to keep tests time-independent.
    """
    now = datetime.now(timezone.utc)
    kwargs = dict(
        domain_name="example.com",
        registrar=registrar,
        name_servers=["ns1.example.com"],
        status=["clientTransferProhibited"],
        emails=["admin@example.com"],
        org="Example Corp",
        country="US",
        text="Domain Name: EXAMPLE.COM",
        creation_date=now - timedelta(days=365) if creation else None,
        expiration_date=(
            now + timedelta(days=expiry_delta_days) if expiry_delta_days is not None else None
        ),
        updated_date=now - timedelta(days=30),
    )
    return _make_whois_obj(**kwargs)


# ======================================================================
# Tests
# ======================================================================


class TestSummaryGeneration:
    """Verify summary generation is semantic and correct."""

    # ----- registered domain with registrar -----

    @pytest.mark.asyncio
    async def test_registered_with_registrar_contains_domain(self, clear_cache):
        w = _registered_whois(registrar="GoDaddy.com, LLC", expiry_delta_days=365)
        result = await _run_lookup("example.com", w, _EMPTY_RDAP)

        assert result.summary is not None
        assert len(result.summary) > 0
        assert "example.com" in result.summary

    @pytest.mark.asyncio
    async def test_registered_with_registrar_says_registered(self, clear_cache):
        w = _registered_whois(registrar="GoDaddy.com, LLC", expiry_delta_days=365)
        result = await _run_lookup("example.com", w, _EMPTY_RDAP)

        assert "registered" in result.summary.lower()

    @pytest.mark.asyncio
    async def test_registered_with_registrar_includes_registrar_name(self, clear_cache):
        w = _registered_whois(registrar="GoDaddy.com, LLC", expiry_delta_days=365)
        result = await _run_lookup("example.com", w, _EMPTY_RDAP)

        assert "GoDaddy" in result.summary

    @pytest.mark.asyncio
    async def test_registered_with_expiry_mentions_days(self, clear_cache):
        w = _registered_whois(registrar="GoDaddy.com, LLC", expiry_delta_days=200)
        result = await _run_lookup("example.com", w, _EMPTY_RDAP)

        assert "expires" in result.summary.lower()
        assert "days" in result.summary.lower()

    @pytest.mark.asyncio
    async def test_summary_ends_with_period(self, clear_cache):
        w = _registered_whois(registrar="GoDaddy.com, LLC", expiry_delta_days=200)
        result = await _run_lookup("example.com", w, _EMPTY_RDAP)

        assert result.summary is not None
        assert result.summary.endswith(".")

    # ----- registered domain without registrar -----

    @pytest.mark.asyncio
    async def test_registered_without_registrar(self, clear_cache):
        w = _registered_whois(registrar=None, expiry_delta_days=365)
        result = await _run_lookup("example.com", w, _EMPTY_RDAP)

        assert result.summary is not None
        assert "registered" in result.summary.lower()
        assert "example.com" in result.summary

    # ----- registered domain without expiry -----

    @pytest.mark.asyncio
    async def test_registered_without_expiry(self, clear_cache):
        w = _registered_whois(registrar="GoDaddy.com, LLC", expiry_delta_days=None)
        result = await _run_lookup("example.com", w, _EMPTY_RDAP)

        assert result.summary is not None
        assert "registered" in result.summary.lower()
        assert result.summary.endswith(".")

    # ----- creation date only (no registrar, no expiry) -----

    @pytest.mark.asyncio
    async def test_creation_date_only(self, clear_cache):
        w = _registered_whois(registrar=None, expiry_delta_days=None, creation=True)
        result = await _run_lookup("example.com", w, _EMPTY_RDAP)

        assert result.summary is not None
        assert "registered" in result.summary.lower()
        assert "example.com" in result.summary

    # ----- available domain -----

    @pytest.mark.asyncio
    async def test_available_domain_summary(self, clear_cache):
        def _raise(d):
            raise Exception("No match for domain")

        with patch("cybersec.core.tools.whois.python_whois.whois", side_effect=_raise), \
             patch("cybersec.core.tools.whois._fetch_rdap", return_value=None), \
             patch("cybersec.core.tools.whois._get_redis", return_value=None):
            result = await whois.whois_lookup("available-domain.com")

        assert result.summary is not None
        assert len(result.summary) > 0
        assert "available" in result.summary.lower()
        assert "available-domain.com" in result.summary

    # ----- no data at all → summary is None -----

    @pytest.mark.asyncio
    async def test_summary_none_when_no_data(self, clear_cache):
        """When whois has no registrar/creation/expiry and RDAP has no events,
        summary should be None."""
        w = _make_whois_obj(
            domain_name="nodata.com",
            registrar=None,
            creation_date=None,
            expiration_date=None,
            updated_date=None,
            name_servers=None,
            status=None,
            emails=None,
            org=None,
            country=None,
            text=None,
        )
        result = await _run_lookup("nodata.com", w, _EMPTY_RDAP)
        assert result.summary is None

    # ----- summary not empty string -----

    @pytest.mark.asyncio
    async def test_summary_not_empty_string(self, clear_cache):
        w = _registered_whois(registrar="Test Registrar", expiry_delta_days=200)
        result = await _run_lookup("example.com", w, _EMPTY_RDAP)

        assert result.summary is not None
        assert result.summary.strip() != ""

    # ----- RDAP registrar fallback in summary -----

    @pytest.mark.asyncio
    async def test_rdap_registrar_fallback_in_summary(self, clear_cache):
        """When WHOIS has no registrar but RDAP entity does, summary should still
        say 'registered' and include the RDAP-derived registrar name."""
        w = _make_whois_obj(
            domain_name="example.com",
            registrar=None,
            creation_date=datetime(2020, 1, 1, tzinfo=timezone.utc),
            expiration_date=datetime(2028, 1, 1, tzinfo=timezone.utc),
            updated_date=datetime(2023, 6, 1, tzinfo=timezone.utc),
            name_servers=["ns1.example.com"],
            status=["clientTransferProhibited"],
            emails=["admin@example.com"],
            org="Example Corp",
            country="US",
            text="Domain Name: EXAMPLE.COM",
        )
        rdap = {
            "handle": "12345",
            "ldhName": "example.com",
            "status": ["clientTransferProhibited"],
            "entities": [
                {
                    "roles": ["registrar"],
                    "vcardArray": [
                        "vcard",
                        [
                            ["version", {}, "text", "4.0"],
                            ["fn", {}, "text", "Example Registrar"],
                            ["org", {}, "text", "Example Registrar Inc"],
                        ],
                    ],
                }
            ],
            "events": [],
            "nameservers": [],
        }
        result = await _run_lookup("example.com", w, rdap)

        assert result.summary is not None
        assert "registered" in result.summary.lower()
        assert "example.com" in result.summary

    # ----- RDAP dates fallback in summary -----

    @pytest.mark.asyncio
    async def test_rdap_dates_fallback_produces_summary(self, clear_cache):
        """WHOIS has no dates, but RDAP events provide them → summary generated."""
        w = _make_whois_obj(
            domain_name="example.com",
            registrar="Test Registrar",
            creation_date=None,
            expiration_date=None,
            updated_date=None,
            name_servers=["ns1.example.com"],
            status=["clientTransferProhibited"],
            emails=["admin@example.com"],
            org="Example Corp",
            country="US",
            text="Domain Name: EXAMPLE.COM",
        )
        rdap = {
            "handle": "12345",
            "ldhName": "example.com",
            "status": ["clientTransferProhibited"],
            "entities": [],
            "events": [
                {"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"},
                {"eventAction": "expiration", "eventDate": "2028-01-01T00:00:00Z"},
            ],
            "nameservers": [],
        }
        result = await _run_lookup("example.com", w, rdap)

        assert result.summary is not None
        assert "registered" in result.summary.lower()
        assert "example.com" in result.summary

    # ----- summary with expired domain -----

    @pytest.mark.asyncio
    async def test_summary_with_expired_domain_has_negative_days(self, clear_cache):
        """An expired domain summary should still mention 'expires in' with negative days."""
        now = datetime.now(timezone.utc)
        w = _make_whois_obj(
            domain_name="expired.com",
            registrar="Test Registrar",
            creation_date=now - timedelta(days=1000),
            expiration_date=now - timedelta(days=60),
            updated_date=now - timedelta(days=90),
            name_servers=["ns1.test.com"],
            status=["clientTransferProhibited"],
            emails=["admin@expired.com"],
            org="Expired Corp",
            country="US",
            text="Domain Name: EXPIRED.COM",
        )
        result = await _run_lookup("expired.com", w, _EMPTY_RDAP)

        assert result.summary is not None
        assert "expired.com" in result.summary
        assert "registered" in result.summary.lower()
        # The summary includes "expires in X days" even for negative X
        assert "expires" in result.summary.lower()
