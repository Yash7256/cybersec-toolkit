"""Integration tests validating fallback behavior when RDAP requests fail."""
from unittest.mock import AsyncMock, patch
import pytest
import httpx

from cybersec.core.tools import whois


@pytest.mark.asyncio
async def test_rdap_timeout_fallback(clear_cache, mock_whois_response):
    """When RDAP times out, whois_lookup still succeeds using WHOIS data."""
    # Arrange
    domain = "example.com"
    
    # Act
    with patch("cybersec.core.tools.whois.python_whois.whois", return_value=mock_whois_response), \
         patch("cybersec.core.tools.whois._fetch_rdap", side_effect=httpx.TimeoutException("Timeout")), \
         patch("cybersec.core.tools.whois._get_redis", return_value=None):
        result = await whois.whois_lookup(domain)

    # Assert
    assert result.rdap_available is False
    assert result.rdap is None
    assert result.registrar == "GoDaddy.com, LLC"
    assert result.error is None
    assert result.normalized["rdap_error"] == "Timeout"


@pytest.mark.asyncio
async def test_rdap_http_404_fallback(clear_cache, mock_whois_response):
    """When RDAP returns None (e.g. 404), whois_lookup still succeeds using WHOIS data."""
    # Arrange
    domain = "example.com"

    # Act
    with patch("cybersec.core.tools.whois.python_whois.whois", return_value=mock_whois_response), \
         patch("cybersec.core.tools.whois._fetch_rdap", return_value=None), \
         patch("cybersec.core.tools.whois._get_redis", return_value=None):
        result = await whois.whois_lookup(domain)

    # Assert
    assert result.rdap_available is False
    assert result.rdap is None
    assert result.registrar == "GoDaddy.com, LLC"
    assert result.error is None
    assert result.normalized["rdap_error"] is None


@pytest.mark.asyncio
async def test_rdap_rate_limit_exception(clear_cache, mock_whois_response):
    """When RDAP raises a rate limit exception, the lookup completes with whois data and logs the error."""
    # Arrange
    domain = "example.com"

    # Act
    with patch("cybersec.core.tools.whois.python_whois.whois", return_value=mock_whois_response), \
         patch("cybersec.core.tools.whois._fetch_rdap", side_effect=RuntimeError("RDAP rate limit reached")), \
         patch("cybersec.core.tools.whois._get_redis", return_value=None):
        result = await whois.whois_lookup(domain)

    # Assert
    assert result.rdap_available is False
    assert result.rdap is None
    assert result.registrar == "GoDaddy.com, LLC"
    assert result.error is None
    assert "RDAP rate limit reached" in result.normalized["rdap_error"]


@pytest.mark.asyncio
async def test_both_whois_and_rdap_fail(clear_cache):
    """When both WHOIS and RDAP queries fail, an error result is returned with logs."""
    # Arrange
    domain = "example.com"

    # Act
    with patch("cybersec.core.tools.whois.python_whois.whois", side_effect=Exception("WHOIS connection refused")), \
         patch("cybersec.core.tools.whois._fetch_rdap", side_effect=Exception("RDAP connection refused")), \
         patch("cybersec.core.tools.whois._get_redis", return_value=None):
        result = await whois.whois_lookup(domain)

    # Assert
    assert result.rdap_available is False
    assert result.rdap is None
    assert result.registrar is None
    assert result.error == "WHOIS connection refused"
    assert result.normalized["whois_error"] == "WHOIS connection refused"
    assert result.normalized["rdap_error"] == "RDAP connection refused"
