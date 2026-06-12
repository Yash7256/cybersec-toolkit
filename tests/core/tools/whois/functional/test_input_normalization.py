"""Functional tests validating target input normalization in whois_lookup."""
from datetime import datetime, timezone
from unittest.mock import patch
import pytest

from cybersec.core.tools import whois
from tests.core.tools.whois.conftest import _make_whois_obj


@pytest.fixture
def mock_normal_response():
    """Mock standard WHOIS response for google.com"""
    return _make_whois_obj(
        domain_name="google.com",
        registrar="MarkMonitor, Inc.",
        creation_date=datetime(1997, 9, 15, 0, 0, 0, tzinfo=timezone.utc),
        expiration_date=datetime(2028, 9, 14, 0, 0, 0, tzinfo=timezone.utc),
        updated_date=datetime(2019, 9, 9, 0, 0, 0, tzinfo=timezone.utc),
        name_servers=["ns1.google.com"],
        status=["clientDeleteProhibited"],
        emails=["abusecomplaints@markmonitor.com"],
        org="Google LLC",
        country="US",
        text="Domain Name: GOOGLE.COM\nRegistrar: MarkMonitor Inc.",
    )


@pytest.fixture
def mock_subdomain_response():
    """Mock standard WHOIS response for sub.google.com"""
    return _make_whois_obj(
        domain_name="sub.google.com",
        registrar="MarkMonitor, Inc.",
        creation_date=datetime(1997, 9, 15, 0, 0, 0, tzinfo=timezone.utc),
        expiration_date=datetime(2028, 9, 14, 0, 0, 0, tzinfo=timezone.utc),
        updated_date=datetime(2019, 9, 9, 0, 0, 0, tzinfo=timezone.utc),
        name_servers=["ns1.google.com"],
        status=["clientDeleteProhibited"],
        emails=["abusecomplaints@markmonitor.com"],
        org="Google LLC",
        country="US",
        text="Domain Name: SUB.GOOGLE.COM\nRegistrar: MarkMonitor Inc.",
    )


@pytest.mark.parametrize("user_input,expected_domain", [
    ("GOOGLE.COM", "google.com"),
    ("google.com", "google.com"),
    ("Google.Com", "google.com"),
    ("https://google.com", "google.com"),
    ("http://google.com", "google.com"),
    ("google.com/", "google.com"),
    ("  google.com  ", "google.com"),
])
@pytest.mark.asyncio
async def test_domain_normalization_variations(clear_cache, mock_normal_response, user_input, expected_domain):
    """Verify that different URL and case formats normalize deterministically to the base domain."""
    # Act
    with patch("cybersec.core.tools.whois.python_whois.whois", return_value=mock_normal_response) as mock_whois, \
         patch("cybersec.core.tools.whois._fetch_rdap", return_value=None), \
         patch("cybersec.core.tools.whois._get_redis", return_value=None):
        result = await whois.whois_lookup(user_input)

    # Assert
    assert result.error is None
    assert result.target == user_input
    assert result.domain == expected_domain
    mock_whois.assert_called_once_with(expected_domain)


@pytest.mark.parametrize("user_input,expected_domain", [
    ("https://www.google.com", "www.google.com"),
    ("www.google.com", "www.google.com"),
])
@pytest.mark.asyncio
async def test_www_subdomain_normalization_variations(clear_cache, mock_subdomain_response, user_input, expected_domain):
    """Verify that www. subdomains normalize correctly."""
    # Act
    with patch("cybersec.core.tools.whois.python_whois.whois", return_value=mock_subdomain_response) as mock_whois, \
         patch("cybersec.core.tools.whois._fetch_rdap", return_value=None), \
         patch("cybersec.core.tools.whois._get_redis", return_value=None):
        result = await whois.whois_lookup(user_input)

    # Assert
    assert result.error is None
    assert result.target == user_input
    assert result.domain == expected_domain
    mock_whois.assert_called_once_with(expected_domain)



@pytest.mark.asyncio
async def test_subdomain_normalization(clear_cache, mock_subdomain_response):
    """Verify that subdomains are correctly preserved during input normalization."""
    # Act
    with patch("cybersec.core.tools.whois.python_whois.whois", return_value=mock_subdomain_response) as mock_whois, \
         patch("cybersec.core.tools.whois._fetch_rdap", return_value=None), \
         patch("cybersec.core.tools.whois._get_redis", return_value=None):
        result = await whois.whois_lookup("sub.google.com")

    # Assert
    assert result.error is None
    assert result.target == "sub.google.com"
    assert result.domain == "sub.google.com"
    mock_whois.assert_called_once_with("sub.google.com")
