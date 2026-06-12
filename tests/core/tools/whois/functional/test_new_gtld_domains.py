"""Functional tests validating modern new gTLDs and newer ccTLDs like .app and .io."""
from datetime import datetime, timezone
from unittest.mock import patch
import pytest

from cybersec.core.tools import whois
from tests.core.tools.whois.conftest import _make_whois_obj


@pytest.fixture
def example_app_response():
    """Mock WHOIS response for example.app"""
    return _make_whois_obj(
        domain_name="example.app",
        registrar="Charleston Road Registry Inc.",
        creation_date=datetime(2018, 5, 8, 0, 0, 0, tzinfo=timezone.utc),
        expiration_date=datetime(2027, 5, 8, 0, 0, 0, tzinfo=timezone.utc),
        updated_date=datetime(2024, 4, 15, 0, 0, 0, tzinfo=timezone.utc),
        name_servers=["ns1.google.com"],
        status=["ok"],
        emails=None,
        org="Charleston Road Registry",
        country="US",
        text="Domain Name: EXAMPLE.APP\nRegistrar: Charleston Road Registry Inc.",
    )


@pytest.fixture
def example_io_response():
    """Mock WHOIS response for example.io"""
    return _make_whois_obj(
        domain_name="example.io",
        registrar="Internet Computer Bureau Ltd.",
        creation_date=datetime(1997, 10, 10, 0, 0, 0, tzinfo=timezone.utc),
        expiration_date=datetime(2026, 10, 10, 0, 0, 0, tzinfo=timezone.utc),
        updated_date=datetime(2023, 9, 20, 0, 0, 0, tzinfo=timezone.utc),
        name_servers=["ns1.io-nic.com"],
        status=["ok"],
        emails=None,
        org="IO NIC",
        country="GB",
        text="Domain Name: EXAMPLE.IO\nRegistrar: Internet Computer Bureau Ltd.",
    )


@pytest.mark.asyncio
async def test_example_app_lookup(clear_cache, example_app_response):
    """Verify that lookup for .app domain succeeds and properly constructs IANA information."""
    # Act
    with patch("cybersec.core.tools.whois.python_whois.whois", return_value=example_app_response), \
         patch("cybersec.core.tools.whois._fetch_rdap", return_value=None), \
         patch("cybersec.core.tools.whois._get_redis", return_value=None):
        result = await whois.whois_lookup("example.app")

    # Assert
    assert result.error is None
    assert result.domain == "example.app"
    assert result.tld == "app"
    assert result.iana is not None
    assert result.iana["iana_url"] == "https://www.iana.org/domains/root/db/app.html"
    assert result.iana["registry_hint"] is None  # Not in local REGISTRY_HINTS
    assert result.available is False


@pytest.mark.asyncio
async def test_example_io_lookup(clear_cache, example_io_response):
    """Verify that lookup for .io domain succeeds and handles the registry hint and IANA database URL."""
    # Act
    with patch("cybersec.core.tools.whois.python_whois.whois", return_value=example_io_response), \
         patch("cybersec.core.tools.whois._fetch_rdap", return_value=None), \
         patch("cybersec.core.tools.whois._get_redis", return_value=None):
        result = await whois.whois_lookup("example.io")

    # Assert
    assert result.error is None
    assert result.domain == "example.io"
    assert result.tld == "io"
    assert result.iana is not None
    assert result.iana["iana_url"] == "https://www.iana.org/domains/root/db/io.html"
    assert result.available is False
