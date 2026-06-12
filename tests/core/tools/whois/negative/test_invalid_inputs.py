"""Negative tests validating behavior for invalid inputs and injection attempts."""
import pytest

from cybersec.core.tools import whois


@pytest.mark.parametrize("invalid_input", [
    "",
    " ",
    "!!!",
    "not_a_domain",
    "..",
    "@@@",
    "////",
    "a" * 254,  # Over 253 characters
])
@pytest.mark.asyncio
async def test_invalid_domain_formats_rejected(invalid_input):
    """Verify that invalid domain structures are rejected and return a valid WHOISResult with an error."""
    # Act
    result = await whois.whois_lookup(invalid_input)

    # Assert
    assert result.domain is None
    assert result.error is not None
    assert "invalid" in result.error.lower() or "required" in result.error.lower() or "long" in result.error.lower()
    assert result.available is None
    assert isinstance(result.name_servers, list)
    assert len(result.name_servers) == 0


@pytest.mark.parametrize("injection_payload", [
    "; rm -rf /",
    "DROP TABLE users;",
    "<script>alert(1)</script>",
    "../../../etc/passwd",
    "example.com;whoami",
    "example.com|ls",
    "example.com&id",
])
@pytest.mark.asyncio
async def test_injection_attempts_rejected(injection_payload):
    """Verify that security injection payloads are rejected gracefully without crashing or executing."""
    # Act
    result = await whois.whois_lookup(injection_payload)

    # Assert
    assert result.domain is None
    assert result.error is not None
    assert "invalid" in result.error.lower()
    assert result.available is None
