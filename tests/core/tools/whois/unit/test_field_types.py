"""Every field matches declared type (str, int, bool, list, dict, None)"""
from unittest.mock import patch

import pytest

from cybersec.core.tools import whois


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_STRING_FIELDS = [
    "target", "domain", "tld", "registrar", "registrar_iana_id",
    "registrar_url", "registrar_abuse_email", "registrar_abuse_phone",
    "creation_date", "expiration_date", "updated_date", "expiry_status",
    "dnssec", "registrant_org", "registrant_country", "raw_text",
    "registry", "summary", "error",
]

_OPTIONAL_STRING_FIELDS = [f for f in _STRING_FIELDS if f != "target"]

_INT_FIELDS = ["domain_age_days", "days_until_expiry"]

_ALWAYS_BOOL_FIELDS = ["privacy_protected", "rdap_available", "cached"]

_LIST_FIELDS = ["name_servers", "status", "status_explanations", "emails", "risk_indicators"]

_OPTIONAL_DICT_FIELDS = ["admin_contact", "tech_contact", "abuse_contact", "rdap", "iana"]

_REQUIRED_DICT_FIELDS = ["historical_whois", "related_domains", "normalized"]


async def _run_lookup(domain, whois_return, rdap_return):
    """Convenience: run whois_lookup with mocked externals, no cache."""
    with patch("cybersec.core.tools.whois.python_whois.whois", return_value=whois_return), \
         patch("cybersec.core.tools.whois._fetch_rdap", return_value=rdap_return), \
         patch("cybersec.core.tools.whois._get_redis", return_value=None):
        return await whois.whois_lookup(domain)


# ======================================================================
# Tests
# ======================================================================


class TestFieldTypes:
    """Verify every field returned by WHOISResult matches its declared type."""

    # ----- registered domain (full data) -----

    @pytest.mark.asyncio
    async def test_string_fields_are_strings_or_none(
        self, clear_cache, mock_whois_response, mock_rdap_response,
    ):
        """String fields should be str or None, never other types."""
        result = await _run_lookup("example.com", mock_whois_response, mock_rdap_response)

        for field in _STRING_FIELDS:
            value = getattr(result, field)
            assert value is None or isinstance(value, str), (
                f"Field '{field}' should be str|None, got {type(value).__name__}: {value!r}"
            )

    @pytest.mark.asyncio
    async def test_integer_fields_are_integers_or_none(
        self, clear_cache, mock_whois_response, mock_rdap_response,
    ):
        """Integer fields should be int or None, never other types."""
        result = await _run_lookup("example.com", mock_whois_response, mock_rdap_response)

        for field in _INT_FIELDS:
            value = getattr(result, field)
            assert value is None or isinstance(value, int), (
                f"Field '{field}' should be int|None, got {type(value).__name__}"
            )

    @pytest.mark.asyncio
    async def test_boolean_fields_are_booleans(
        self, clear_cache, mock_whois_response, mock_rdap_response,
    ):
        """privacy_protected, rdap_available, cached must always be bool."""
        result = await _run_lookup("example.com", mock_whois_response, mock_rdap_response)

        for field in _ALWAYS_BOOL_FIELDS:
            value = getattr(result, field)
            assert isinstance(value, bool), (
                f"Field '{field}' should be bool, got {type(value).__name__}"
            )

    @pytest.mark.asyncio
    async def test_available_field_is_bool_or_none(
        self, clear_cache, mock_whois_response, mock_rdap_response,
    ):
        """``available`` is ``bool | None``."""
        result = await _run_lookup("example.com", mock_whois_response, mock_rdap_response)
        assert result.available is None or isinstance(result.available, bool)

    @pytest.mark.asyncio
    async def test_list_fields_are_always_lists(
        self, clear_cache, mock_whois_response, mock_rdap_response,
    ):
        """List fields must always be list, never None."""
        result = await _run_lookup("example.com", mock_whois_response, mock_rdap_response)

        for field in _LIST_FIELDS:
            value = getattr(result, field)
            assert isinstance(value, list), (
                f"Field '{field}' should be list, got {type(value).__name__}"
            )

    @pytest.mark.asyncio
    async def test_list_element_types_name_servers(
        self, clear_cache, mock_whois_response, mock_rdap_response,
    ):
        """name_servers elements are strings."""
        result = await _run_lookup("example.com", mock_whois_response, mock_rdap_response)
        assert len(result.name_servers) > 0
        for ns in result.name_servers:
            assert isinstance(ns, str)

    @pytest.mark.asyncio
    async def test_list_element_types_status(
        self, clear_cache, mock_whois_response, mock_rdap_response,
    ):
        """status elements are strings."""
        result = await _run_lookup("example.com", mock_whois_response, mock_rdap_response)
        assert len(result.status) > 0
        for s in result.status:
            assert isinstance(s, str)

    @pytest.mark.asyncio
    async def test_list_element_types_status_explanations(
        self, clear_cache, mock_whois_response, mock_rdap_response,
    ):
        """status_explanations elements are dicts with 'status' and 'meaning' keys."""
        result = await _run_lookup("example.com", mock_whois_response, mock_rdap_response)
        assert len(result.status_explanations) > 0
        for item in result.status_explanations:
            assert isinstance(item, dict)
            assert "status" in item
            assert "meaning" in item

    @pytest.mark.asyncio
    async def test_list_element_types_emails(
        self, clear_cache, mock_whois_response, mock_rdap_response,
    ):
        """emails elements are strings."""
        result = await _run_lookup("example.com", mock_whois_response, mock_rdap_response)
        assert len(result.emails) > 0
        for e in result.emails:
            assert isinstance(e, str)

    @pytest.mark.asyncio
    async def test_list_element_types_risk_indicators(
        self, clear_cache, mock_whois_response, empty_rdap_response,
    ):
        """risk_indicators elements are dicts with 'id', 'severity', 'label'."""
        # Use empty RDAP so no duplicate statuses; the whois response with a
        # TLD of "com" won't trigger unusual_tld but the dates may trigger
        # something.  We just need to verify structure if any exist.
        result = await _run_lookup("example.com", mock_whois_response, empty_rdap_response)
        for risk in result.risk_indicators:
            assert isinstance(risk, dict)
            assert "id" in risk
            assert "severity" in risk
            assert "label" in risk

    # ----- dict fields -----

    @pytest.mark.asyncio
    async def test_optional_dict_fields(
        self, clear_cache, mock_whois_response, mock_rdap_response,
    ):
        """admin_contact, tech_contact, abuse_contact, rdap, iana → dict|None."""
        result = await _run_lookup("example.com", mock_whois_response, mock_rdap_response)
        for field in _OPTIONAL_DICT_FIELDS:
            value = getattr(result, field)
            assert value is None or isinstance(value, dict), (
                f"Field '{field}' should be dict|None, got {type(value).__name__}"
            )

    @pytest.mark.asyncio
    async def test_required_dict_fields_always_dicts(
        self, clear_cache, mock_whois_response, mock_rdap_response,
    ):
        """historical_whois, related_domains, normalized → always dict."""
        result = await _run_lookup("example.com", mock_whois_response, mock_rdap_response)
        for field in _REQUIRED_DICT_FIELDS:
            value = getattr(result, field)
            assert isinstance(value, dict), (
                f"Field '{field}' should be dict, got {type(value).__name__}"
            )

    # ----- partial data: lists stay lists, optional fields become None -----

    @pytest.mark.asyncio
    async def test_list_fields_are_lists_with_partial_data(
        self, clear_cache, partial_response, empty_rdap_response,
    ):
        """List fields must be lists even when whois data is mostly None."""
        result = await _run_lookup("partial.com", partial_response, empty_rdap_response)
        for field in _LIST_FIELDS:
            value = getattr(result, field)
            assert isinstance(value, list), (
                f"Field '{field}' should be list with partial data, got {type(value).__name__}"
            )

    @pytest.mark.asyncio
    async def test_optional_fields_none_with_partial_data(
        self, clear_cache, partial_response, empty_rdap_response,
    ):
        """Optional string/int fields should be None when no data is available."""
        result = await _run_lookup("partial.com", partial_response, empty_rdap_response)

        # These should be None when no upstream data exists
        assert result.registrar is None
        assert result.creation_date is None
        assert result.expiration_date is None
        assert result.updated_date is None
        assert result.domain_age_days is None
        assert result.days_until_expiry is None
        assert result.expiry_status is None

    # ----- target always a string -----

    @pytest.mark.asyncio
    async def test_target_field_preserved_as_given(self, clear_cache):
        """target field should be the original input string verbatim."""
        result = await _run_lookup("example.com", None, None)
        assert isinstance(result.target, str)
        assert result.target == "example.com"

    # ----- malformed data still produces valid types -----

    @pytest.mark.asyncio
    async def test_malformed_data_produces_valid_types(
        self, clear_cache, malformed_response, empty_rdap_response,
    ):
        """Even with malformed input, output fields have correct types."""
        result = await _run_lookup("malformed.com", malformed_response, empty_rdap_response)

        assert isinstance(result.target, str)
        assert result.domain is None or isinstance(result.domain, str)
        assert isinstance(result.name_servers, list)
        assert isinstance(result.status, list)
        assert isinstance(result.status_explanations, list)
        assert isinstance(result.emails, list)
        assert isinstance(result.risk_indicators, list)
        assert isinstance(result.privacy_protected, bool)
        assert isinstance(result.rdap_available, bool)
        assert isinstance(result.cached, bool)
        assert isinstance(result.historical_whois, dict)
        assert isinstance(result.related_domains, dict)
        assert isinstance(result.normalized, dict)

    # ----- error result type contract -----

    @pytest.mark.asyncio
    async def test_error_result_types(self, clear_cache):
        """_empty_result should produce correct types for all fields."""
        result = await _run_lookup("", None, None)  # triggers ValueError → empty result
        # Verify the error result has correct types
        assert isinstance(result.target, str)
        assert isinstance(result.name_servers, list)
        assert isinstance(result.status, list)
        assert isinstance(result.emails, list)
        assert isinstance(result.risk_indicators, list)
        assert isinstance(result.historical_whois, dict)
        assert isinstance(result.related_domains, dict)
        assert isinstance(result.normalized, dict)
        assert isinstance(result.privacy_protected, bool)
        assert isinstance(result.cached, bool)
        assert result.error is not None
        assert isinstance(result.error, str)
