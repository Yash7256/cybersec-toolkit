"""Negative tests validating behavior for None input."""
import pytest

from cybersec.core.tools import whois


@pytest.mark.asyncio
async def test_none_input_handled_gracefully():
    """Verify that passing None does not raise an AttributeError and is handled gracefully."""
    # Act
    result = await whois.whois_lookup(None)

    # Assert
    assert result.domain is None
    assert result.error is not None
    assert "required" in result.error.lower()
    assert result.available is None
