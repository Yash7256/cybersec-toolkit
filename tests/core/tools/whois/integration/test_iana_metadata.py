"""Integration tests validating IANA metadata generation for supported and unusual TLDs."""
from unittest.mock import patch
import pytest

from cybersec.core.tools import whois
from tests.core.tools.whois.conftest import _make_whois_obj


@pytest.mark.parametrize("domain,expected_tld,expected_hint", [
    ("test-domain.com", "com", "Verisign"),
    ("my-org.org", "org", "Public Interest Registry"),
    ("verisign-net.net", "net", "Verisign"),
    ("harvard.edu", "edu", "Educause"),
    ("whitehouse.gov", "gov", "Cybersecurity and Infrastructure Security Agency"),
    ("bbc.uk", "uk", "Nominet"),
    ("nic.in", "in", "National Internet Exchange of India"),
])
@pytest.mark.asyncio
async def test_supported_tlds_iana_metadata(clear_cache, domain, expected_tld, expected_hint):
    """Verify registry hints and IANA links are correctly generated for supported TLDs."""
    # Arrange
    whois_response = _make_whois_obj(
        domain_name=domain,
        registrar="Test Registrar",
        creation_date=None,
        expiration_date=None,
        updated_date=None,
        name_servers=[],
        status=[],
        emails=[],
        org=None,
        country=None,
        text=None,
    )

    # Act
    with patch("cybersec.core.tools.whois.python_whois.whois", return_value=whois_response), \
         patch("cybersec.core.tools.whois._fetch_rdap", return_value=None), \
         patch("cybersec.core.tools.whois._get_redis", return_value=None):
        result = await whois.whois_lookup(domain)

    # Assert
    assert result.tld == expected_tld
    assert result.iana is not None
    assert result.iana["tld"] == expected_tld
    assert result.iana["iana_url"] == f"https://www.iana.org/domains/root/db/{expected_tld}.html"
    assert result.iana["registry_hint"] == expected_hint
    assert result.iana["metadata_source"] == "local mapping plus IANA root-db link"


@pytest.mark.asyncio
async def test_unsupported_tld_no_hint(clear_cache):
    """Verify that an unsupported/unusual TLD (e.g. xyz) is handled gracefully without local hints."""
    # Arrange
    domain = "unusual-domain.xyz"
    whois_response = _make_whois_obj(
        domain_name=domain,
        registrar="Test Registrar",
        creation_date=None,
        expiration_date=None,
        updated_date=None,
        name_servers=[],
        status=[],
        emails=[],
        org=None,
        country=None,
        text=None,
    )

    # Act
    with patch("cybersec.core.tools.whois.python_whois.whois", return_value=whois_response), \
         patch("cybersec.core.tools.whois._fetch_rdap", return_value=None), \
         patch("cybersec.core.tools.whois._get_redis", return_value=None):
        result = await whois.whois_lookup(domain)

    # Assert
    assert result.tld == "xyz"
    assert result.iana is not None
    assert result.iana["tld"] == "xyz"
    assert result.iana["registry_hint"] is None
    assert result.registry is None


@pytest.mark.asyncio
async def test_unsupported_tld_fallback_to_rdap_port43(clear_cache):
    """Verify registry hint is derived from RDAP port43 field when TLD is not locally supported."""
    # Arrange
    domain = "unusual-domain.xyz"
    whois_response = _make_whois_obj(
        domain_name=domain,
        registrar="Test Registrar",
        creation_date=None,
        expiration_date=None,
        updated_date=None,
        name_servers=[],
        status=[],
        emails=[],
        org=None,
        country=None,
        text=None,
    )
    rdap_response = {
        "handle": "12345",
        "ldhName": domain,
        "port43": "whois.nic.xyz",
        "entities": [],
        "events": [],
    }

    # Act
    with patch("cybersec.core.tools.whois.python_whois.whois", return_value=whois_response), \
         patch("cybersec.core.tools.whois._fetch_rdap", return_value=rdap_response), \
         patch("cybersec.core.tools.whois._get_redis", return_value=None):
        result = await whois.whois_lookup(domain)

    # Assert
    assert result.tld == "xyz"
    assert result.registry == "whois.nic.xyz"
    assert result.iana is not None
    assert result.iana["registry_hint"] == "whois.nic.xyz"


@pytest.mark.asyncio
async def test_invalid_domain_format_gives_no_iana_metadata(clear_cache):
    """Verify that malformed/invalid domains do not raise exceptions and return None for IANA metadata."""
    # Act
    result = await whois.whois_lookup("invalid_domain_name")

    # Assert
    assert result.tld is None
    assert result.iana is None
    assert result.error is not None
