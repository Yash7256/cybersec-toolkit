"""privacy_protected flag detection"""
from datetime import datetime, timezone
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


_STANDARD_DATES = dict(
    creation_date=datetime(2020, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
    expiration_date=datetime(2028, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
    updated_date=datetime(2023, 6, 1, 0, 0, 0, tzinfo=timezone.utc),
)

_EMPTY_RDAP = {
    "handle": "EMPTY",
    "ldhName": "privacy-domain.com",
    "status": ["clientTransferProhibited"],
    "entities": [],
    "events": [],
    "nameservers": [],
}


def _base_whois(**overrides):
    """Build a whois-like object with sensible defaults + overrides."""
    defaults = dict(
        domain_name="privacy-domain.com",
        registrar="GoDaddy.com, LLC",
        name_servers=["ns1.example.com"],
        status=["clientTransferProhibited"],
        emails=["admin@example.com"],
        org="Example Corp",
        country="US",
        text="Domain Name: PRIVACY-DOMAIN.COM",
        **_STANDARD_DATES,
    )
    defaults.update(overrides)
    return _make_whois_obj(**defaults)


# ======================================================================
# Direct _privacy_detected() tests
# ======================================================================


class TestPrivacyDetectedDirect:
    """Test ``_privacy_detected()`` pure function directly."""

    def test_domains_by_proxy(self):
        assert whois._privacy_detected("Domains By Proxy, LLC") is True

    def test_redacted(self):
        assert whois._privacy_detected("REDACTED FOR PRIVACY") is True

    def test_whoisguard(self):
        assert whois._privacy_detected("whoisguard@namecheap.com") is True

    def test_contact_privacy(self):
        assert whois._privacy_detected("Contact Privacy Inc.") is True

    def test_data_protected(self):
        assert whois._privacy_detected("Data Protected") is True

    def test_private_registration(self):
        assert whois._privacy_detected("Private Registration Service") is True

    def test_withheld(self):
        assert whois._privacy_detected("WITHHELD FOR PRIVACY") is True

    def test_no_privacy_indicators(self):
        assert whois._privacy_detected("Example Corporation", "admin@example.com") is False

    def test_case_insensitive(self):
        assert whois._privacy_detected("DOMAINS BY PROXY, LLC") is True

    def test_multiple_values_first_matches(self):
        assert whois._privacy_detected("Normal Org", "admin@example.com", "Domains By Proxy, LLC") is True

    def test_none_values_handled(self):
        assert whois._privacy_detected(None, None, None) is False

    def test_empty_strings(self):
        assert whois._privacy_detected("", "", "") is False


# ======================================================================
# Privacy detection through whois_lookup()
# ======================================================================


class TestPrivacyDetection:
    """Verify privacy_protected flag through full whois_lookup()."""

    @pytest.mark.asyncio
    async def test_privacy_in_registrant_org(self, clear_cache):
        w = _base_whois(org="Domains By Proxy, LLC")
        result = await _run_lookup("privacy-domain.com", w, _EMPTY_RDAP)
        assert result.privacy_protected is True

    @pytest.mark.asyncio
    async def test_privacy_in_emails(self, clear_cache):
        w = _base_whois(emails=["privacy@domainsbyproxy.com"])
        result = await _run_lookup("privacy-domain.com", w, _EMPTY_RDAP)
        assert result.privacy_protected is True

    @pytest.mark.asyncio
    async def test_privacy_in_raw_text(self, clear_cache):
        w = _base_whois(
            text="Domain Name: PRIVACY-DOMAIN.COM\nRegistrant Organization: Domains By Proxy, LLC",
        )
        result = await _run_lookup("privacy-domain.com", w, _EMPTY_RDAP)
        assert result.privacy_protected is True

    @pytest.mark.asyncio
    async def test_privacy_in_admin_contact_via_rdap(self, clear_cache):
        """Privacy detected through RDAP admin contact."""
        w = _base_whois()
        rdap = {
            "handle": "12345",
            "ldhName": "privacy-domain.com",
            "status": ["clientTransferProhibited"],
            "entities": [
                {
                    "roles": ["administrative"],
                    "vcardArray": [
                        "vcard",
                        [
                            ["version", {}, "text", "4.0"],
                            ["fn", {}, "text", "Privacy Protected"],
                            ["email", {}, "text", "privacy@domainsbyproxy.com"],
                        ],
                    ],
                }
            ],
            "events": [],
            "nameservers": [],
        }
        result = await _run_lookup("privacy-domain.com", w, rdap)
        assert result.privacy_protected is True

    @pytest.mark.asyncio
    async def test_privacy_in_tech_contact_via_rdap(self, clear_cache):
        """Privacy detected through RDAP tech contact."""
        w = _base_whois()
        rdap = {
            "handle": "12345",
            "ldhName": "privacy-domain.com",
            "status": ["clientTransferProhibited"],
            "entities": [
                {
                    "roles": ["technical"],
                    "vcardArray": [
                        "vcard",
                        [
                            ["version", {}, "text", "4.0"],
                            ["fn", {}, "text", "Whoisguard Protected"],
                        ],
                    ],
                }
            ],
            "events": [],
            "nameservers": [],
        }
        result = await _run_lookup("privacy-domain.com", w, rdap)
        assert result.privacy_protected is True

    @pytest.mark.asyncio
    async def test_no_privacy_when_no_patterns(self, clear_cache, mock_whois_response, mock_rdap_response):
        """privacy_protected is False when org/emails/text have no privacy keywords."""
        result = await _run_lookup("example.com", mock_whois_response, mock_rdap_response)
        assert result.privacy_protected is False

    @pytest.mark.asyncio
    async def test_no_privacy_with_all_none_fields(self, clear_cache, partial_response, empty_rdap_response):
        """privacy_protected is False when all fields are None."""
        result = await _run_lookup("partial.com", partial_response, empty_rdap_response)
        assert result.privacy_protected is False

    @pytest.mark.asyncio
    async def test_redacted_org_triggers_privacy(self, clear_cache):
        w = _base_whois(org="REDACTED FOR PRIVACY")
        result = await _run_lookup("privacy-domain.com", w, _EMPTY_RDAP)
        assert result.privacy_protected is True

    @pytest.mark.asyncio
    async def test_whoisguard_email_triggers_privacy(self, clear_cache):
        w = _base_whois(emails=["whoisguard@namecheap.com"])
        result = await _run_lookup("privacy-domain.com", w, _EMPTY_RDAP)
        assert result.privacy_protected is True

    @pytest.mark.asyncio
    async def test_private_registration_in_text_triggers_privacy(self, clear_cache):
        w = _base_whois(text="Domain Name: X\nPrivate Registration Service")
        result = await _run_lookup("privacy-domain.com", w, _EMPTY_RDAP)
        assert result.privacy_protected is True

    @pytest.mark.asyncio
    async def test_data_protected_in_text_triggers_privacy(self, clear_cache):
        w = _base_whois(text="Domain Name: X\nData Protected")
        result = await _run_lookup("privacy-domain.com", w, _EMPTY_RDAP)
        assert result.privacy_protected is True

    @pytest.mark.asyncio
    async def test_withheld_in_text_triggers_privacy(self, clear_cache):
        w = _base_whois(text="Registrant Name: WITHHELD FOR PRIVACY")
        result = await _run_lookup("privacy-domain.com", w, _EMPTY_RDAP)
        assert result.privacy_protected is True

    @pytest.mark.asyncio
    async def test_privacy_case_insensitive(self, clear_cache):
        """Upper-case org still triggers privacy."""
        w = _base_whois(org="DOMAINS BY PROXY, LLC")
        result = await _run_lookup("privacy-domain.com", w, _EMPTY_RDAP)
        assert result.privacy_protected is True

    @pytest.mark.asyncio
    async def test_contact_privacy_pattern(self, clear_cache):
        w = _base_whois(org="Contact Privacy Inc. Customer 12345")
        result = await _run_lookup("privacy-domain.com", w, _EMPTY_RDAP)
        assert result.privacy_protected is True
