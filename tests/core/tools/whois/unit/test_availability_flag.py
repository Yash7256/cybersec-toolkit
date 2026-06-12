"""available flag when domain is unregistered"""
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


async def _run_lookup_whois_error(domain, error_msg, rdap_return=None):
    """Run whois_lookup where python_whois.whois raises *error_msg*."""
    def _raise(d):
        raise Exception(error_msg)

    with patch("cybersec.core.tools.whois.python_whois.whois", side_effect=_raise), \
         patch("cybersec.core.tools.whois._fetch_rdap", return_value=rdap_return), \
         patch("cybersec.core.tools.whois._get_redis", return_value=None):
        return await whois.whois_lookup(domain)


# ======================================================================
# Tests
# ======================================================================


class TestAvailabilityFlag:
    """Verify ``available`` flag behaviour for registered and unregistered domains."""

    # ----- available == True: error contains availability keywords -----

    @pytest.mark.asyncio
    async def test_available_true_no_match(self, clear_cache):
        result = await _run_lookup_whois_error(
            "available-domain.com", "No match for domain AVAILABLE-DOMAIN.COM",
        )
        assert result.available is True

    @pytest.mark.asyncio
    async def test_available_true_not_found(self, clear_cache):
        result = await _run_lookup_whois_error(
            "available-domain.com", "Domain not found",
        )
        assert result.available is True

    @pytest.mark.asyncio
    async def test_available_true_available_keyword(self, clear_cache):
        result = await _run_lookup_whois_error(
            "available-domain.com", "Domain available",
        )
        assert result.available is True

    @pytest.mark.asyncio
    async def test_available_true_unregistered_keyword(self, clear_cache):
        """The word 'available' is a substring checked in code; 'unregistered'
        is NOT checked by the implementation – only 'no match', 'not found',
        and 'available' are.  Verify actual behaviour."""
        result = await _run_lookup_whois_error(
            "available-domain.com", "Domain unregistered",
        )
        # The implementation checks for ("no match", "not found", "available")
        # "unregistered" does NOT contain any of those substrings
        assert result.available is None

    @pytest.mark.asyncio
    async def test_available_true_case_insensitive(self, clear_cache):
        result = await _run_lookup_whois_error(
            "available-domain.com", "NO MATCH FOR DOMAIN",
        )
        assert result.available is True

    @pytest.mark.asyncio
    async def test_available_true_partial_match(self, clear_cache):
        result = await _run_lookup_whois_error(
            "available-domain.com", "Error: Domain not found in registry",
        )
        assert result.available is True

    # ----- available == False: WHOIS or RDAP returns data -----

    @pytest.mark.asyncio
    async def test_available_false_when_whois_succeeds(
        self, clear_cache, mock_whois_response,
    ):
        result = await _run_lookup("example.com", mock_whois_response, None)
        assert result.available is False

    @pytest.mark.asyncio
    async def test_available_false_when_rdap_succeeds(
        self, clear_cache, mock_rdap_response,
    ):
        """WHOIS returns None but RDAP provides data."""
        # Simulate WHOIS failure + RDAP success
        def _raise(d):
            raise Exception("Connection refused")

        with patch("cybersec.core.tools.whois.python_whois.whois", side_effect=_raise), \
             patch("cybersec.core.tools.whois._fetch_rdap", return_value=mock_rdap_response), \
             patch("cybersec.core.tools.whois._get_redis", return_value=None):
            result = await whois.whois_lookup("example.com")

        assert result.available is False

    @pytest.mark.asyncio
    async def test_available_false_when_both_succeed(
        self, clear_cache, mock_whois_response, mock_rdap_response,
    ):
        result = await _run_lookup("example.com", mock_whois_response, mock_rdap_response)
        assert result.available is False

    @pytest.mark.asyncio
    async def test_available_false_when_partial_whois(
        self, clear_cache, partial_response,
    ):
        """Even a partial WHOIS response (truthy object) → available=False."""
        result = await _run_lookup("partial.com", partial_response, None)
        assert result.available is False

    # ----- available == None: ambiguous / non-availability errors -----

    @pytest.mark.asyncio
    async def test_available_none_connection_timeout(self, clear_cache):
        result = await _run_lookup_whois_error("example.com", "Connection timeout")
        assert result.available is None

    @pytest.mark.asyncio
    async def test_available_none_connection_refused(self, clear_cache):
        result = await _run_lookup_whois_error("example.com", "Connection refused")
        assert result.available is None

    @pytest.mark.asyncio
    async def test_available_none_server_error(self, clear_cache):
        result = await _run_lookup_whois_error("example.com", "Internal server error")
        assert result.available is None

    @pytest.mark.asyncio
    async def test_available_none_when_both_fail_without_availability_keywords(
        self, clear_cache,
    ):
        """Both WHOIS and RDAP fail; error doesn't indicate availability."""
        def whois_err(d):
            raise Exception("Connection refused")

        async def rdap_err(d):
            raise Exception("RDAP server error")

        with patch("cybersec.core.tools.whois.python_whois.whois", side_effect=whois_err), \
             patch("cybersec.core.tools.whois._fetch_rdap", side_effect=rdap_err), \
             patch("cybersec.core.tools.whois._get_redis", return_value=None):
            result = await whois.whois_lookup("example.com")

        assert result.available is None

    # ----- WHOIS timeout + RDAP fallback -----

    @pytest.mark.asyncio
    async def test_available_false_whois_timeout_rdap_success(
        self, clear_cache, mock_rdap_response,
    ):
        """WHOIS times out → w=None, but RDAP succeeds → available=False."""
        import asyncio

        with patch("cybersec.core.tools.whois.python_whois.whois", side_effect=Exception("timeout")), \
             patch("cybersec.core.tools.whois._fetch_rdap", return_value=mock_rdap_response), \
             patch("cybersec.core.tools.whois._get_redis", return_value=None):
            result = await whois.whois_lookup("example.com")

        assert result.available is False

    # ----- RDAP returns None (404 mapping) + WHOIS availability error -----

    @pytest.mark.asyncio
    async def test_available_true_rdap_none_whois_not_found(self, clear_cache):
        """RDAP returns None (404) + WHOIS says 'not found' → available=True."""
        result = await _run_lookup_whois_error(
            "available-domain.com", "No match for domain", rdap_return=None,
        )
        assert result.available is True

    # ----- Error field set when available=True -----

    @pytest.mark.asyncio
    async def test_error_none_when_available(self, clear_cache):
        """When available=True, error should be None (availability is not an error)."""
        result = await _run_lookup_whois_error(
            "available-domain.com", "No match for domain",
        )
        assert result.available is True
        assert result.error is None

    # ----- Error field set when truly failed -----

    @pytest.mark.asyncio
    async def test_error_set_when_both_fail(self, clear_cache):
        """When both WHOIS and RDAP fail and it's not an availability signal, error is set."""
        result = await _run_lookup_whois_error("example.com", "Connection refused")
        assert result.error is not None
        assert isinstance(result.error, str)
