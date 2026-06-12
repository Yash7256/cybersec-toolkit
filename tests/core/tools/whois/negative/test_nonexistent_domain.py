"""Negative tests validating behavior for nonexistent/unregistered domains."""
from unittest.mock import patch
import pytest

from cybersec.core.tools import whois


@pytest.mark.asyncio
async def test_nonexistent_domain_detection(clear_cache):
    """Verify that a nonexistent domain raising a 'No match' error is handled as available."""
    # Arrange
    err_msg = "No match for domain nonexistent123456.com"

    # Act
    with patch("cybersec.core.tools.whois.python_whois.whois", side_effect=Exception(err_msg)), \
         patch("cybersec.core.tools.whois._fetch_rdap", return_value=None), \
         patch("cybersec.core.tools.whois._get_redis", return_value=None):
        result = await whois.whois_lookup("nonexistent123456.com")

    # Assert
    assert result.error is None
    assert result.domain == "nonexistent123456.com"
    assert result.available is True
    assert "available" in result.summary.lower()
    assert result.registrar is None


@pytest.mark.asyncio
async def test_nonexistent_domain_not_found_exception(clear_cache):
    """Verify that a nonexistent domain raising a 'Not found' error is handled as available."""
    # Arrange
    err_msg = "Domain Not found"

    # Act
    with patch("cybersec.core.tools.whois.python_whois.whois", side_effect=Exception(err_msg)), \
         patch("cybersec.core.tools.whois._fetch_rdap", return_value=None), \
         patch("cybersec.core.tools.whois._get_redis", return_value=None):
        result = await whois.whois_lookup("nonexistent123456.com")

    # Assert
    assert result.error is None
    assert result.domain == "nonexistent123456.com"
    assert result.available is True
    assert "available" in result.summary.lower()
