"""Shared fixtures: mock WHOISResult, sample domains, patched network calls"""
import sys
# Clean sys.path and sys.modules to prevent naming collision with python-whois library.
# pytest might prepend tests/core/tools to sys.path, causing "import whois" to load our test folder instead of the python-whois library.
sys.path = [p for p in sys.path if not (p.endswith("tests/core/tools") or p.endswith("tests/core/tools/whois"))]
if "whois" in sys.modules:
    mod = sys.modules["whois"]
    if mod and hasattr(mod, "__file__") and mod.__file__ and "tests/core/tools/whois" in mod.__file__:
        del sys.modules["whois"]

import asyncio
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
import pytest

from cybersec.core.tools import whois



# ---------------------------------------------------------------------------
# Fixed reference time
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_datetime_now():
    """Fixed datetime for deterministic calculations"""
    return datetime(2024, 6, 15, 12, 0, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Domain-name string fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def registered_domain():
    """A standard registered domain with complete data"""
    return "example.com"


@pytest.fixture
def expired_domain():
    """A domain that has expired"""
    return "expired-domain.com"


@pytest.fixture
def expiring_domain():
    """A domain expiring soon (within 30 days)"""
    return "expiring-domain.com"


@pytest.fixture
def newly_registered_domain():
    """A domain registered within last 30 days"""
    return "new-domain.com"


@pytest.fixture
def privacy_domain():
    """A domain with privacy protection"""
    return "privacy-domain.com"


@pytest.fixture
def unregistered_domain():
    """A domain that is available/unregistered"""
    return "available-domain.com"


# ---------------------------------------------------------------------------
# Factory helper – creates whois-like objects with explicit attributes only
# ---------------------------------------------------------------------------

def _make_whois_obj(**kwargs):
    """Create a SimpleNamespace that behaves like a python-whois result.

    Unlike MagicMock, accessing an attribute that was *not* explicitly set
    will raise AttributeError, which makes ``getattr(w, name, default)``
    return the *default* as expected by the production code.
    """
    return SimpleNamespace(**kwargs)


@pytest.fixture
def make_whois_obj():
    """Factory fixture returning ``_make_whois_obj`` for ad-hoc use."""
    return _make_whois_obj


# ---------------------------------------------------------------------------
# Pre-built whois response fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_whois_response():
    """Mock python-whois response for a registered domain"""
    return _make_whois_obj(
        domain_name="example.com",
        registrar="GoDaddy.com, LLC",
        registrar_iana_id="146",
        registrar_url="https://www.godaddy.com",
        creation_date=datetime(2020, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
        expiration_date=datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
        updated_date=datetime(2023, 6, 1, 0, 0, 0, tzinfo=timezone.utc),
        name_servers=["ns1.example.com", "ns2.example.com"],
        status=["clientTransferProhibited", "clientUpdateProhibited"],
        emails=["admin@example.com"],
        org="Example Corporation",
        country="US",
        text="Domain Name: EXAMPLE.COM\nRegistrar: GoDaddy.com, LLC",
    )


@pytest.fixture
def mock_expired_whois_response():
    """Mock python-whois response for an expired domain"""
    return _make_whois_obj(
        domain_name="expired-domain.com",
        registrar="NameCheap, Inc.",
        creation_date=datetime(2019, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
        expiration_date=datetime(2023, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
        updated_date=datetime(2022, 12, 1, 0, 0, 0, tzinfo=timezone.utc),
        name_servers=["ns1.namecheap.com"],
        status=["clientTransferProhibited"],
        emails=["admin@expired.com"],
        org=None,
        country=None,
        text="Domain Name: EXPIRED-DOMAIN.COM",
    )


@pytest.fixture
def mock_expiring_whois_response(mock_datetime_now):
    """Mock python-whois response for a domain expiring soon"""
    return _make_whois_obj(
        domain_name="expiring-domain.com",
        registrar="GoDaddy.com, LLC",
        creation_date=datetime(2020, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
        expiration_date=mock_datetime_now + timedelta(days=15),
        updated_date=datetime(2023, 12, 1, 0, 0, 0, tzinfo=timezone.utc),
        name_servers=["ns1.example.com"],
        status=["clientTransferProhibited"],
        emails=["admin@expiring.com"],
        org="Expiring Corp",
        country="US",
        text="Domain Name: EXPIRING-DOMAIN.COM",
    )


@pytest.fixture
def mock_new_whois_response(mock_datetime_now):
    """Mock python-whois response for a newly registered domain"""
    return _make_whois_obj(
        domain_name="new-domain.com",
        registrar="Cloudflare, Inc.",
        creation_date=mock_datetime_now - timedelta(days=10),
        expiration_date=mock_datetime_now + timedelta(days=350),
        updated_date=mock_datetime_now - timedelta(days=10),
        name_servers=["ns1.cloudflare.com"],
        status=["clientTransferProhibited"],
        emails=["admin@new.com"],
        org="New Startup",
        country="US",
        text="Domain Name: NEW-DOMAIN.COM",
    )


@pytest.fixture
def mock_privacy_whois_response():
    """Mock python-whois response for a privacy-protected domain"""
    return _make_whois_obj(
        domain_name="privacy-domain.com",
        registrar="GoDaddy.com, LLC",
        creation_date=datetime(2020, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
        expiration_date=datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
        updated_date=datetime(2023, 6, 1, 0, 0, 0, tzinfo=timezone.utc),
        name_servers=["ns1.example.com"],
        status=["clientTransferProhibited"],
        emails=["privacy@domainsbyproxy.com"],
        org="Domains By Proxy, LLC",
        country=None,
        text="Domain Name: PRIVACY-DOMAIN.COM\nRegistrant Organization: Domains By Proxy, LLC",
    )


# ---------------------------------------------------------------------------
# RDAP response fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_rdap_response():
    """Mock RDAP response for enrichment"""
    return {
        "handle": "12345_DOMAIN_COM-VRSN",
        "ldhName": "example.com",
        "status": ["clientTransferProhibited", "clientUpdateProhibited"],
        "entities": [
            {
                "roles": ["registrar"],
                "vcardArray": [
                    "vcard",
                    [
                        ["version", {}, "text", "4.0"],
                        ["fn", {}, "text", "GoDaddy.com, LLC"],
                        ["org", {}, "text", "GoDaddy.com, LLC"],
                        ["email", {}, "text", "abuse@godaddy.com"],
                        ["tel", {}, "text", "+1.4805058800"],
                    ],
                ],
            },
            {
                "roles": ["abuse"],
                "vcardArray": [
                    "vcard",
                    [
                        ["version", {}, "text", "4.0"],
                        ["fn", {}, "text", "Abuse Contact"],
                        ["email", {}, "text", "abuse@godaddy.com"],
                    ],
                ],
            },
        ],
        "events": [
            {"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2025-01-01T00:00:00Z"},
            {"eventAction": "last changed", "eventDate": "2023-06-01T00:00:00Z"},
        ],
        "nameservers": [
            {"ldhName": "ns1.example.com"},
            {"ldhName": "ns2.example.com"},
        ],
        "secureDNS": {"delegationSigned": True},
        "port43": "whois.godaddy.com",
    }


@pytest.fixture
def mock_rdap_response_no_entities():
    """Mock RDAP response without entities (but WITH events for date fallback)"""
    return {
        "handle": "12345_DOMAIN_COM-VRSN",
        "ldhName": "example.com",
        "status": ["clientTransferProhibited"],
        "entities": [],
        "events": [
            {"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2025-01-01T00:00:00Z"},
        ],
        "nameservers": [{"ldhName": "ns1.example.com"}],
    }


@pytest.fixture
def empty_rdap_response():
    """Truly minimal RDAP response: no entities, no events, no nameservers.

    Use this when testing scenarios where RDAP should NOT provide fallback data.
    """
    return {
        "handle": "EMPTY",
        "ldhName": "example.com",
        "status": [],
        "entities": [],
        "events": [],
        "nameservers": [],
    }


# ---------------------------------------------------------------------------
# Partial / malformed whois responses
# ---------------------------------------------------------------------------

@pytest.fixture
def partial_response():
    """Whois response with partial data – every optional field is absent or None.

    Uses SimpleNamespace so that accessing an *unset* attribute raises
    AttributeError (which makes ``getattr(w, attr, default)`` return
    the default).  This is critical: MagicMock silently invents truthy
    attributes, causing incorrect type coercions in production code.
    """
    return _make_whois_obj(
        domain_name="partial.com",
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


@pytest.fixture
def malformed_response():
    """Mock WHOIS response with malformed data"""
    return _make_whois_obj(
        domain_name="malformed.com",
        registrar=12345,            # Wrong type (int instead of str)
        creation_date="invalid-date",
        expiration_date="also-invalid",
        updated_date="not-a-date",
        name_servers="ns1.example.com",   # String instead of list
        status="clientTransferProhibited",  # String instead of list
        emails="admin@example.com",        # String instead of list
        org="",
        country="",
        text="",
    )


# ---------------------------------------------------------------------------
# Redis / httpx mocks
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_redis():
    """Mock Redis client"""
    redis = AsyncMock()
    redis.get = AsyncMock(return_value=None)
    redis.setex = AsyncMock()
    return redis


@pytest.fixture
def mock_httpx_client():
    """Mock httpx.AsyncClient for RDAP requests"""
    client = AsyncMock()
    response = AsyncMock()
    response.status_code = 200
    response.json.return_value = {}
    response.raise_for_status = MagicMock()
    client.get.return_value = response
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock()
    return client


# ---------------------------------------------------------------------------
# Cache helpers
# ---------------------------------------------------------------------------

@pytest.fixture
def clear_cache():
    """Clear WHOIS cache before and after each test"""
    whois.clear_whois_cache()
    yield
    whois.clear_whois_cache()


# ---------------------------------------------------------------------------
# Relative-date fixtures for time-independent computed-field tests
# ---------------------------------------------------------------------------

@pytest.fixture
def relative_now():
    """The real 'now' at test time — use with relative date fixtures."""
    return datetime.now(timezone.utc)


@pytest.fixture
def healthy_whois(relative_now):
    """Whois response whose expiration is 365 days in the future."""
    return _make_whois_obj(
        domain_name="healthy.com",
        registrar="Test Registrar, LLC",
        creation_date=relative_now - timedelta(days=1000),
        expiration_date=relative_now + timedelta(days=365),
        updated_date=relative_now - timedelta(days=60),
        name_servers=["ns1.test.com", "ns2.test.com"],
        status=["clientTransferProhibited"],
        emails=["admin@healthy.com"],
        org="Healthy Corp",
        country="US",
        text="Domain Name: HEALTHY.COM",
    )


@pytest.fixture
def expiring_soon_whois(relative_now):
    """Whois response whose expiration is 15 days in the future."""
    return _make_whois_obj(
        domain_name="expiring.com",
        registrar="Test Registrar, LLC",
        creation_date=relative_now - timedelta(days=500),
        expiration_date=relative_now + timedelta(days=15),
        updated_date=relative_now - timedelta(days=60),
        name_servers=["ns1.test.com"],
        status=["clientTransferProhibited"],
        emails=["admin@expiring.com"],
        org="Expiring Corp",
        country="US",
        text="Domain Name: EXPIRING.COM",
    )


@pytest.fixture
def expired_whois(relative_now):
    """Whois response whose expiration is 60 days in the past."""
    return _make_whois_obj(
        domain_name="expired.com",
        registrar="Test Registrar, LLC",
        creation_date=relative_now - timedelta(days=1000),
        expiration_date=relative_now - timedelta(days=60),
        updated_date=relative_now - timedelta(days=90),
        name_servers=["ns1.test.com"],
        status=["clientTransferProhibited"],
        emails=["admin@expired.com"],
        org="Expired Corp",
        country="US",
        text="Domain Name: EXPIRED.COM",
    )


@pytest.fixture
def newly_registered_whois(relative_now):
    """Whois response created 5 days ago."""
    return _make_whois_obj(
        domain_name="newdomain.com",
        registrar="Cloudflare, Inc.",
        creation_date=relative_now - timedelta(days=5),
        expiration_date=relative_now + timedelta(days=360),
        updated_date=relative_now - timedelta(days=5),
        name_servers=["ns1.cloudflare.com"],
        status=["clientTransferProhibited"],
        emails=["admin@newdomain.com"],
        org="New Startup",
        country="US",
        text="Domain Name: NEWDOMAIN.COM",
    )


# ---------------------------------------------------------------------------
# Full mock-lookup fixture (for other test categories)
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_whois_lookup():
    """Mock the entire whois_lookup function for integration-style unit tests"""
    async def _mock_lookup(domain: str) -> whois.WHOISResult:
        return whois.WHOISResult(
            target=domain,
            domain=domain,
            tld="com",
            registrar="Test Registrar",
            registrar_iana_id="999",
            registrar_url="https://test.example.com",
            registrar_abuse_email="abuse@test.example.com",
            registrar_abuse_phone="+1.5555555555",
            creation_date="2020-01-01T00:00:00+00:00",
            expiration_date="2025-01-01T00:00:00+00:00",
            updated_date="2023-06-01T00:00:00+00:00",
            domain_age_days=1626,
            days_until_expiry=200,
            expiry_status="healthy",
            name_servers=["ns1.test.com", "ns2.test.com"],
            dnssec="signed",
            status=["clientTransferProhibited"],
            status_explanations=[{
                "status": "clientTransferProhibited",
                "meaning": "Domain transfer is locked by the registrar."
            }],
            emails=["admin@test.com"],
            registrant_org="Test Org",
            registrant_country="US",
            admin_contact={"name": "Admin", "email": "admin@test.com"},
            tech_contact={"name": "Tech", "email": "tech@test.com"},
            abuse_contact={"name": "Abuse", "email": "abuse@test.com"},
            privacy_protected=False,
            raw_text="Domain Name: TEST.COM",
            rdap={"handle": "12345"},
            rdap_available=True,
            registry="Test Registry",
            iana={"tld": "com", "iana_url": "https://www.iana.org/domains/root/db/com.html"},
            available=False,
            historical_whois={"available": False, "reason": "Requires paid provider"},
            related_domains={"available": False, "reason": "Requires paid provider"},
            risk_indicators=[],
            summary="test.com is registered with Test Registrar and expires in 200 days.",
            normalized={"source_priority": "WHOIS with RDAP fallback/enrichment"},
            cached=False,
            error=None,
        )
    return _mock_lookup
