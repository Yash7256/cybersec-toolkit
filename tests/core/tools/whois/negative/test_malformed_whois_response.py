"""Negative tests validating behavior for malformed WHOIS response payloads."""
from unittest.mock import patch
import pytest

from cybersec.core.tools import whois


@pytest.mark.asyncio
async def test_malformed_fields_parsing_resilience(clear_cache, malformed_response):
    """Verify that type-mismatched or corrupted fields in WHOIS are handled gracefully without crashing."""
    # Act
    with patch("cybersec.core.tools.whois.python_whois.whois", return_value=malformed_response), \
         patch("cybersec.core.tools.whois._fetch_rdap", return_value=None), \
         patch("cybersec.core.tools.whois._get_redis", return_value=None):
        result = await whois.whois_lookup("malformed.com")

    # Assert
    assert result.error is None
    assert result.domain == "malformed.com"
    
    # 1. Registrar passed as integer 12345 -> should be co-erced/parsed gracefully
    assert result.registrar == "12345"

    # 2. String instead of list for name_servers -> should listify
    assert isinstance(result.name_servers, list)
    assert result.name_servers == ["ns1.example.com"]

    # 3. String instead of list for emails -> should listify
    assert isinstance(result.emails, list)
    assert result.emails == ["admin@example.com"]

    # 4. String instead of list for status -> should listify
    assert isinstance(result.status, list)
    assert result.status == ["clientTransferProhibited"]

    # 5. Invalid date formats -> should be None
    assert result.creation_date is None
    assert result.expiration_date is None
    assert result.updated_date is None
    assert result.domain_age_days is None
    assert result.days_until_expiry is None
    assert result.expiry_status is None
