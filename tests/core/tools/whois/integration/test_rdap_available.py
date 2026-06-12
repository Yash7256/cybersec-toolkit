"""Integration tests validating behavior when RDAP data is available and fully parsed."""
from unittest.mock import AsyncMock, patch
import pytest

from cybersec.core.tools import whois


@pytest.mark.asyncio
async def test_rdap_available_flag_and_payload(clear_cache, mock_whois_response, mock_rdap_response):
    """When RDAP successfully responds, rdap_available is True and payload is populated."""
    # Arrange
    domain = "example.com"
    
    # Add a phone number to the abuse contact in RDAP
    rdap = mock_rdap_response.copy()
    rdap["entities"] = [
        rdap["entities"][0],  # registrar
        {
            "roles": ["abuse"],
            "vcardArray": [
                "vcard",
                [
                    ["version", {}, "text", "4.0"],
                    ["fn", {}, "text", "Abuse Contact"],
                    ["email", {}, "text", "abuse@godaddy.com"],
                    ["tel", {}, "text", "+1.4805058800"],
                ],
            ],
        }
    ]
    
    # Act
    with patch("cybersec.core.tools.whois.python_whois.whois", return_value=mock_whois_response), \
         patch("cybersec.core.tools.whois._fetch_rdap", return_value=rdap), \
         patch("cybersec.core.tools.whois._get_redis", return_value=None):
        result = await whois.whois_lookup(domain)
        
    # Assert
    assert result.rdap_available is True
    assert result.rdap == rdap
    assert result.dnssec == "signed"
    assert result.registrar_abuse_email == "abuse@godaddy.com"
    assert result.registrar_abuse_phone == "+1.4805058800"



@pytest.mark.asyncio
async def test_rdap_dnssec_unsigned(clear_cache, mock_whois_response, mock_rdap_response):
    """Verify dnssec value is 'unsigned' when delegationSigned is False."""
    # Arrange
    domain = "example.com"
    rdap_unsigned = mock_rdap_response.copy()
    rdap_unsigned["secureDNS"] = {"delegationSigned": False}

    # Act
    with patch("cybersec.core.tools.whois.python_whois.whois", return_value=mock_whois_response), \
         patch("cybersec.core.tools.whois._fetch_rdap", return_value=rdap_unsigned), \
         patch("cybersec.core.tools.whois._get_redis", return_value=None):
        result = await whois.whois_lookup(domain)

    # Assert
    assert result.dnssec == "unsigned"


@pytest.mark.asyncio
async def test_rdap_nameservers_fallback(clear_cache, mock_rdap_response):
    """If WHOIS response lacks nameservers but RDAP has them, they fallback to RDAP."""
    # Arrange
    domain = "example.com"
    # Create a WHOIS response with NO name servers
    from tests.core.tools.whois.conftest import _make_whois_obj
    whois_no_ns = _make_whois_obj(
        domain_name="example.com",
        registrar="GoDaddy.com, LLC",
        name_servers=None,  # missing
        status=["clientTransferProhibited"],
        emails=["admin@example.com"],
        org="Example Corporation",
        country="US",
        text="Domain Name: EXAMPLE.COM",
    )

    # Act
    with patch("cybersec.core.tools.whois.python_whois.whois", return_value=whois_no_ns), \
         patch("cybersec.core.tools.whois._fetch_rdap", return_value=mock_rdap_response), \
         patch("cybersec.core.tools.whois._get_redis", return_value=None):
        result = await whois.whois_lookup(domain)

    # Assert
    assert len(result.name_servers) == 2
    assert "ns1.example.com" in result.name_servers
    assert "ns2.example.com" in result.name_servers


@pytest.mark.asyncio
async def test_rdap_contacts_populated(clear_cache, mock_whois_response, mock_rdap_response):
    """Verify admin, tech, and abuse contacts are extracted correctly from RDAP."""
    # Arrange
    domain = "example.com"
    # Let's add admin and tech contacts to RDAP response entities
    rdap = mock_rdap_response.copy()
    rdap["entities"] = list(rdap["entities"]) + [
        {
            "roles": ["administrative"],
            "vcardArray": [
                "vcard",
                [
                    ["version", {}, "text", "4.0"],
                    ["fn", {}, "text", "Admin Name"],
                    ["email", {}, "text", "admin@example.com"],
                ],
            ],
        },
        {
            "roles": ["technical"],
            "vcardArray": [
                "vcard",
                [
                    ["version", {}, "text", "4.0"],
                    ["fn", {}, "text", "Tech Name"],
                    ["email", {}, "text", "tech@example.com"],
                ],
            ],
        }
    ]

    # Act
    with patch("cybersec.core.tools.whois.python_whois.whois", return_value=mock_whois_response), \
         patch("cybersec.core.tools.whois._fetch_rdap", return_value=rdap), \
         patch("cybersec.core.tools.whois._get_redis", return_value=None):
        result = await whois.whois_lookup(domain)

    # Assert
    assert result.admin_contact is not None
    assert result.admin_contact["name"] == "Admin Name"
    assert result.admin_contact["email"] == "admin@example.com"
    
    assert result.tech_contact is not None
    assert result.tech_contact["name"] == "Tech Name"
    assert result.tech_contact["email"] == "tech@example.com"

    assert result.abuse_contact is not None
    assert result.abuse_contact["name"] == "GoDaddy.com, LLC" or result.abuse_contact["email"] == "abuse@godaddy.com"
