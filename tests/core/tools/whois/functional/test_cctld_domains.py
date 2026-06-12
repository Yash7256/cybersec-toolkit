"""Functional tests validating country-code Top Level Domains (ccTLDs) like .uk and .in."""
from datetime import datetime, timezone
from unittest.mock import patch
import pytest

from cybersec.core.tools import whois
from tests.core.tools.whois.conftest import _make_whois_obj


@pytest.fixture
def bbc_co_uk_response():
    """Mock WHOIS response for bbc.co.uk"""
    return _make_whois_obj(
        domain_name="bbc.co.uk",
        registrar="Nominet",
        creation_date=datetime(1996, 8, 1, 0, 0, 0, tzinfo=timezone.utc),
        expiration_date=datetime(2027, 8, 1, 0, 0, 0, tzinfo=timezone.utc),
        updated_date=datetime(2024, 7, 10, 0, 0, 0, tzinfo=timezone.utc),
        name_servers=["ns1.bbc.co.uk", "ns2.bbc.co.uk"],
        status=["ok"],
        emails=None,
        org="British Broadcasting Corporation",
        country="United Kingdom",
        text="Domain name: bbc.co.uk\nRegistrar: Nominet",
    )


@pytest.fixture
def tcs_in_response():
    """Mock WHOIS response for tcs.in"""
    return _make_whois_obj(
        domain_name="tcs.in",
        registrar="National Internet Exchange of India",
        creation_date=datetime(2004, 5, 27, 0, 0, 0, tzinfo=timezone.utc),
        expiration_date=datetime(2029, 5, 27, 0, 0, 0, tzinfo=timezone.utc),
        updated_date=datetime(2023, 5, 20, 0, 0, 0, tzinfo=timezone.utc),
        name_servers=["ns1.tcs.in", "ns2.tcs.in"],
        status=["ok"],
        emails=None,
        org="Tata Consultancy Services Limited",
        country="IN",
        text="Domain Name: TCS.IN\nRegistrar: National Internet Exchange of India",
    )


@pytest.mark.asyncio
async def test_bbc_co_uk_lookup(clear_cache, bbc_co_uk_response):
    """Verify that multi-level ccTLD domains like bbc.co.uk parse correctly and return Nominet hints."""
    # Act
    with patch("cybersec.core.tools.whois.python_whois.whois", return_value=bbc_co_uk_response), \
         patch("cybersec.core.tools.whois._fetch_rdap", return_value=None), \
         patch("cybersec.core.tools.whois._get_redis", return_value=None):
        result = await whois.whois_lookup("bbc.co.uk")

    # Assert
    assert result.error is None
    assert result.domain == "bbc.co.uk"
    assert result.registrar == "Nominet"
    assert result.tld == "uk"  # last part
    assert result.iana is not None
    assert result.iana["registry_hint"] == "Nominet"
    assert result.iana["iana_url"] == "https://www.iana.org/domains/root/db/uk.html"
    assert result.registrant_org == "British Broadcasting Corporation"
    assert result.available is False


@pytest.mark.asyncio
async def test_tcs_in_lookup(clear_cache, tcs_in_response):
    """Verify that .in ccTLD domains like tcs.in resolve and parse correctly with registry hints."""
    # Act
    with patch("cybersec.core.tools.whois.python_whois.whois", return_value=tcs_in_response), \
         patch("cybersec.core.tools.whois._fetch_rdap", return_value=None), \
         patch("cybersec.core.tools.whois._get_redis", return_value=None):
        result = await whois.whois_lookup("tcs.in")

    # Assert
    assert result.error is None
    assert result.domain == "tcs.in"
    assert result.registrar == "National Internet Exchange of India"
    assert result.tld == "in"
    assert result.iana is not None
    assert result.iana["registry_hint"] == "National Internet Exchange of India"
    assert result.registrant_country == "IN"
    assert result.available is False
