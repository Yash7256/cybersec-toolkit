"""Integration tests verifying merge precedence and logic between WHOIS and RDAP responses."""
from datetime import datetime, timezone
from unittest.mock import patch
import pytest

from cybersec.core.tools import whois
from tests.core.tools.whois.conftest import _make_whois_obj


@pytest.mark.asyncio
async def test_merge_priority_whois_precedence(clear_cache):
    """Verify WHOIS values override conflicting RDAP values for common fields."""
    # Arrange
    domain = "example.com"
    whois_response = _make_whois_obj(
        domain_name="example.com",
        registrar="GoDaddy.com, LLC",
        creation_date=datetime(2020, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
        expiration_date=datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
        updated_date=datetime(2023, 6, 1, 0, 0, 0, tzinfo=timezone.utc),
        name_servers=["ns1.whois-ns.com"],
        status=["clientTransferProhibited"],
        emails=["admin@example.com"],
        org="Example Corporation",
        country="US",
        text="Domain Name: EXAMPLE.COM",
    )
    rdap_response = {
        "handle": "12345",
        "ldhName": "example.com",
        "status": ["active"],
        "entities": [
            {
                "roles": ["registrar"],
                "vcardArray": [
                    "vcard",
                    [
                        ["version", {}, "text", "4.0"],
                        ["fn", {}, "text", "RDAP Registrar"],
                    ],
                ],
            }
        ],
        "events": [
            {"eventAction": "registration", "eventDate": "2021-01-01T00:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2026-01-01T00:00:00Z"},
            {"eventAction": "last changed", "eventDate": "2024-01-01T00:00:00Z"},
        ],
        "nameservers": [{"ldhName": "ns1.rdap-ns.com"}],
    }

    # Act
    with patch("cybersec.core.tools.whois.python_whois.whois", return_value=whois_response), \
         patch("cybersec.core.tools.whois._fetch_rdap", return_value=rdap_response), \
         patch("cybersec.core.tools.whois._get_redis", return_value=None):
        result = await whois.whois_lookup(domain)

    # Assert
    assert result.registrar == "GoDaddy.com, LLC"
    assert result.creation_date == "2020-01-01T00:00:00+00:00"
    assert result.expiration_date == "2025-01-01T00:00:00+00:00"
    assert result.updated_date == "2023-06-01T00:00:00+00:00"
    assert "ns1.whois-ns.com" in result.name_servers
    assert "ns1.rdap-ns.com" not in result.name_servers
    assert "clientTransferProhibited" in result.status
    assert "active" not in result.status


@pytest.mark.asyncio
async def test_merge_fallback_to_rdap_when_whois_missing(clear_cache):
    """Verify RDAP values are used for missing WHOIS fields."""
    # Arrange
    domain = "example.com"
    whois_response = _make_whois_obj(
        domain_name="example.com",
        registrar=None,  # missing
        creation_date=None,  # missing
        expiration_date=None,  # missing
        updated_date=None,  # missing
        name_servers=None,  # missing
        status=None,  # missing
        emails=None,
        org=None,
        country=None,
        text=None,
    )
    rdap_response = {
        "handle": "12345",
        "ldhName": "example.com",
        "status": ["active"],
        "entities": [
            {
                "roles": ["registrar"],
                "vcardArray": [
                    "vcard",
                    [
                        ["version", {}, "text", "4.0"],
                        ["fn", {}, "text", "RDAP Registrar"],
                    ],
                ],
            }
        ],
        "events": [
            {"eventAction": "registration", "eventDate": "2021-01-01T00:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2026-01-01T00:00:00Z"},
            {"eventAction": "last changed", "eventDate": "2024-01-01T00:00:00Z"},
        ],
        "nameservers": [{"ldhName": "ns1.rdap-ns.com"}],
    }

    # Act
    with patch("cybersec.core.tools.whois.python_whois.whois", return_value=whois_response), \
         patch("cybersec.core.tools.whois._fetch_rdap", return_value=rdap_response), \
         patch("cybersec.core.tools.whois._get_redis", return_value=None):
        result = await whois.whois_lookup(domain)

    # Assert
    assert result.registrar == "RDAP Registrar"
    assert result.creation_date == "2021-01-01T00:00:00+00:00"
    assert result.expiration_date == "2026-01-01T00:00:00+00:00"
    assert result.updated_date == "2024-01-01T00:00:00+00:00"

    assert "ns1.rdap-ns.com" in result.name_servers
    assert "active" in result.status


@pytest.mark.asyncio
async def test_merge_no_data_returns_none(clear_cache):
    """Verify that when both WHOIS and RDAP lack fields, they remain None or empty list."""
    # Arrange
    domain = "example.com"
    whois_response = _make_whois_obj(
        domain_name="example.com",
        registrar=None,
        creation_date=None,
        expiration_date=None,
        updated_date=None,
        name_servers=None,
        status=None,
        emails=None,
        org=None,
        country=None,
        text=None,
    )
    rdap_response = {
        "handle": "12345",
        "ldhName": "example.com",
        "entities": [],
        "events": [],
        "nameservers": [],
    }

    # Act
    with patch("cybersec.core.tools.whois.python_whois.whois", return_value=whois_response), \
         patch("cybersec.core.tools.whois._fetch_rdap", return_value=rdap_response), \
         patch("cybersec.core.tools.whois._get_redis", return_value=None):
        result = await whois.whois_lookup(domain)

    # Assert
    assert result.registrar is None
    assert result.creation_date is None
    assert result.expiration_date is None
    assert result.updated_date is None
    assert result.name_servers == []
    assert result.status == []
