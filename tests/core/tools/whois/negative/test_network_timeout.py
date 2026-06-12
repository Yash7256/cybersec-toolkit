"""Negative tests validating behavior during network timeouts."""
import socket
from unittest.mock import patch
import httpx
import pytest

from cybersec.core.tools import whois


@pytest.mark.asyncio
async def test_whois_timeout_rdap_success(clear_cache, mock_rdap_response):
    """Verify that a WHOIS socket timeout falls back to RDAP data if available."""
    # Act
    with patch("cybersec.core.tools.whois.python_whois.whois", side_effect=socket.timeout("Connection timed out")), \
         patch("cybersec.core.tools.whois._fetch_rdap", return_value=mock_rdap_response), \
         patch("cybersec.core.tools.whois._get_redis", return_value=None):
        result = await whois.whois_lookup("example.com")

    # Assert
    assert result.error is None  # Handled by RDAP fallback
    assert result.domain == "example.com"
    assert result.rdap_available is True
    assert result.dnssec == "signed"
    assert result.normalized["source_priority"] == "WHOIS with RDAP fallback/enrichment"


@pytest.mark.asyncio
async def test_rdap_timeout_whois_success(clear_cache, mock_whois_response):
    """Verify that an RDAP timeout does not crash the lookup and falls back to WHOIS data."""
    # Act
    with patch("cybersec.core.tools.whois.python_whois.whois", return_value=mock_whois_response), \
         patch("cybersec.core.tools.whois._fetch_rdap", side_effect=httpx.ConnectTimeout("RDAP timed out")), \
         patch("cybersec.core.tools.whois._get_redis", return_value=None):
        result = await whois.whois_lookup("example.com")

    # Assert
    assert result.error is None  # Handled by WHOIS data
    assert result.domain == "example.com"
    assert result.rdap_available is False
    assert result.normalized["rdap_error"] == "RDAP timed out"
    assert result.normalized["source_priority"] == "WHOIS with RDAP fallback/enrichment"


@pytest.mark.asyncio
async def test_both_services_timeout(clear_cache):
    """Verify that when both services time out, the lookup fails gracefully with a populated error."""
    # Act
    with patch("cybersec.core.tools.whois.python_whois.whois", side_effect=TimeoutError("WHOIS down")), \
         patch("cybersec.core.tools.whois._fetch_rdap", side_effect=httpx.ConnectTimeout("RDAP down")), \
         patch("cybersec.core.tools.whois._get_redis", return_value=None):
        result = await whois.whois_lookup("example.com")

    # Assert
    assert result.domain == "example.com"
    assert result.error is not None
    assert "timed out" in result.error.lower()


@pytest.mark.asyncio
async def test_both_services_general_failure(clear_cache):
    """Verify that general exceptions in both services populate the error field."""
    # Act
    with patch("cybersec.core.tools.whois.python_whois.whois", side_effect=Exception("WHOIS connection failed")), \
         patch("cybersec.core.tools.whois._fetch_rdap", side_effect=Exception("RDAP connection failed")), \
         patch("cybersec.core.tools.whois._get_redis", return_value=None):
        result = await whois.whois_lookup("example.com")

    # Assert
    assert result.domain == "example.com"
    assert result.error is not None
    assert "WHOIS connection failed" in result.error

