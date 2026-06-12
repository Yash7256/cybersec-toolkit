"""Functional tests validating standard registered domains (e.g., google.com, github.com)."""
from datetime import datetime, timezone
from unittest.mock import patch
import pytest

from cybersec.core.tools import whois
from tests.core.tools.whois.conftest import _make_whois_obj


@pytest.fixture
def google_com_response():
    """Realistic WHOIS response for google.com"""
    return _make_whois_obj(
        domain_name="google.com",
        registrar="MarkMonitor, Inc.",
        creation_date=datetime(1997, 9, 15, 0, 0, 0, tzinfo=timezone.utc),
        expiration_date=datetime(2028, 9, 14, 0, 0, 0, tzinfo=timezone.utc),
        updated_date=datetime(2019, 9, 9, 0, 0, 0, tzinfo=timezone.utc),
        name_servers=["ns1.google.com", "ns2.google.com", "ns3.google.com", "ns4.google.com"],
        status=["clientDeleteProhibited", "clientTransferProhibited", "clientUpdateProhibited"],
        emails=["abusecomplaints@markmonitor.com"],
        org="Google LLC",
        country="US",
        text="Domain Name: GOOGLE.COM\nRegistrar: MarkMonitor Inc.",
    )


@pytest.fixture
def github_com_response():
    """Realistic WHOIS response for github.com"""
    return _make_whois_obj(
        domain_name="github.com",
        registrar="MarkMonitor, Inc.",
        creation_date=datetime(2007, 10, 9, 0, 0, 0, tzinfo=timezone.utc),
        expiration_date=datetime(2026, 10, 9, 0, 0, 0, tzinfo=timezone.utc),
        updated_date=datetime(2023, 9, 5, 0, 0, 0, tzinfo=timezone.utc),
        name_servers=["dns1.p01.nsone.net", "dns2.p01.nsone.net"],
        status=["clientDeleteProhibited", "clientTransferProhibited", "clientUpdateProhibited"],
        emails=["abusecomplaints@markmonitor.com"],
        org="GitHub, Inc.",
        country="US",
        text="Domain Name: GITHUB.COM\nRegistrar: MarkMonitor Inc.",
    )


@pytest.mark.asyncio
async def test_google_com_lookup(clear_cache, google_com_response):
    """Verify standard google.com WHOIS lookup parses all core attributes correctly."""
    # Act
    with patch("cybersec.core.tools.whois.python_whois.whois", return_value=google_com_response), \
         patch("cybersec.core.tools.whois._fetch_rdap", return_value=None), \
         patch("cybersec.core.tools.whois._get_redis", return_value=None):
        result = await whois.whois_lookup("google.com")

    # Assert
    assert result.error is None
    assert result.domain == "google.com"
    assert result.registrar == "MarkMonitor, Inc."
    assert result.creation_date == "1997-09-15T00:00:00+00:00"
    assert result.expiration_date == "2028-09-14T00:00:00+00:00"
    assert result.available is False
    assert result.privacy_protected is False
    assert result.tld == "com"
    assert "google.com" in result.summary.lower()
    assert "markmonitor" in result.summary.lower()
    assert len(result.name_servers) == 4
    assert "ns1.google.com" in result.name_servers


@pytest.mark.asyncio
async def test_github_com_lookup(clear_cache, github_com_response):
    """Verify standard github.com WHOIS lookup parses core attributes correctly."""
    # Act
    with patch("cybersec.core.tools.whois.python_whois.whois", return_value=github_com_response), \
         patch("cybersec.core.tools.whois._fetch_rdap", return_value=None), \
         patch("cybersec.core.tools.whois._get_redis", return_value=None):
        result = await whois.whois_lookup("github.com")

    # Assert
    assert result.error is None
    assert result.domain == "github.com"
    assert result.registrar == "MarkMonitor, Inc."
    assert result.creation_date == "2007-10-09T00:00:00+00:00"
    assert result.expiration_date == "2026-10-09T00:00:00+00:00"
    assert result.available is False
    assert result.tld == "com"
    assert len(result.name_servers) == 2
    assert "dns1.p01.nsone.net" in result.name_servers
    assert "github.com" in result.summary.lower()
