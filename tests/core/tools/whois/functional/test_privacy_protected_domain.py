"""Functional tests validating WHOIS behavior for privacy-protected domains."""
from unittest.mock import patch
import pytest

from cybersec.core.tools import whois


@pytest.mark.asyncio
async def test_privacy_protected_domain_lookup(clear_cache, mock_privacy_whois_response):
    """Verify that a privacy-protected domain is identified and flags are set correctly."""
    # Act
    with patch("cybersec.core.tools.whois.python_whois.whois", return_value=mock_privacy_whois_response), \
         patch("cybersec.core.tools.whois._fetch_rdap", return_value=None), \
         patch("cybersec.core.tools.whois._get_redis", return_value=None):
        result = await whois.whois_lookup("privacy-domain.com")

    # Assert
    assert result.error is None
    assert result.domain == "privacy-domain.com"
    assert result.privacy_protected is True
    assert "privacy" in result.summary.lower()
    
    # Check risk indicators
    risk_ids = [risk["id"] for risk in result.risk_indicators]
    assert "privacy_protected" in risk_ids
    privacy_risk = next(risk for risk in result.risk_indicators if risk["id"] == "privacy_protected")
    assert privacy_risk["severity"] == "info"


@pytest.mark.asyncio
async def test_non_private_domain_lookup(clear_cache, mock_whois_response):
    """Verify that a standard public domain registration does not trigger privacy protection flags."""
    # Act
    with patch("cybersec.core.tools.whois.python_whois.whois", return_value=mock_whois_response), \
         patch("cybersec.core.tools.whois._fetch_rdap", return_value=None), \
         patch("cybersec.core.tools.whois._get_redis", return_value=None):
        result = await whois.whois_lookup("example.com")

    # Assert
    assert result.error is None
    assert result.domain == "example.com"
    assert result.privacy_protected is False
    
    # Check risk indicators
    risk_ids = [risk["id"] for risk in result.risk_indicators]
    assert "privacy_protected" not in risk_ids
