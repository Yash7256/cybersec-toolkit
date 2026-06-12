"""Functional tests validating WHOIS behavior for expired domains."""
from unittest.mock import patch
import pytest

from cybersec.core.tools import whois


@pytest.mark.asyncio
async def test_expired_domain_lookup(clear_cache, expired_whois):
    """Verify that an expired domain lookup populates expiry status, days until expiry, and risk indicators."""
    # Act
    with patch("cybersec.core.tools.whois.python_whois.whois", return_value=expired_whois), \
         patch("cybersec.core.tools.whois._fetch_rdap", return_value=None), \
         patch("cybersec.core.tools.whois._get_redis", return_value=None):
        result = await whois.whois_lookup("expired.com")

    # Assert
    assert result.error is None
    assert result.domain == "expired.com"
    assert result.expiry_status == "expired"
    assert result.days_until_expiry is not None
    assert result.days_until_expiry <= 0
    assert "expired" in result.summary.lower()
    
    # Check risk indicators
    risk_ids = [risk["id"] for risk in result.risk_indicators]
    assert "expired" in risk_ids
    expired_risk = next(risk for risk in result.risk_indicators if risk["id"] == "expired")
    assert expired_risk["severity"] == "high"
