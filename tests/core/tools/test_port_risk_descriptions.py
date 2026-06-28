"""
Regression tests for port_risk.py and port_descriptions.py.

(a) Registry-consistency: classify_port_risk and get_port_description must
    return values that match PORT_REGISTRY for every registered port.
(b) Fallback: port 31337 (not in PORT_REGISTRY) must fall through to the
    keyword/generic fallback logic unchanged.
"""
import pytest

from cybersec.core.tools.port_registry import PORT_REGISTRY
from cybersec.core.tools.port_risk import classify_port_risk
from cybersec.core.tools.port_descriptions import get_port_description


# ---------------------------------------------------------------------------
# (a) Registry-consistency tests
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("port, info", PORT_REGISTRY.items())
def test_classify_port_risk_matches_registry(port, info):
    """classify_port_risk must return the risk_level and risk_reason from PORT_REGISTRY."""
    level, reason = classify_port_risk(port, info.service)
    assert level == info.risk_level, (
        f"port {port}: expected risk_level={info.risk_level!r}, got {level!r}"
    )
    assert reason == info.risk_reason, (
        f"port {port}: expected risk_reason={info.risk_reason!r}, got {reason!r}"
    )


@pytest.mark.parametrize("port, info", PORT_REGISTRY.items())
def test_get_port_description_matches_registry(port, info):
    """get_port_description must return purpose and security_concern from PORT_REGISTRY."""
    desc = get_port_description(port, info.service)
    assert desc.purpose == info.purpose, (
        f"port {port}: expected purpose={info.purpose!r}, got {desc.purpose!r}"
    )
    assert desc.security_concern == info.security_concern, (
        f"port {port}: expected security_concern={info.security_concern!r}, "
        f"got {desc.security_concern!r}"
    )


# ---------------------------------------------------------------------------
# (b) Fallback tests — port 31337 is not in PORT_REGISTRY
# ---------------------------------------------------------------------------

def test_classify_port_risk_fallback_unknown_port():
    """Port 31337 (not in registry) must fall through to the generic fallback."""
    assert 31337 not in PORT_REGISTRY
    level, reason = classify_port_risk(31337)
    assert level == "medium"
    assert "31337" in reason


def test_classify_port_risk_fallback_keyword_match():
    """Port 31337 with a service name containing 'redis' must match the keyword fallback."""
    assert 31337 not in PORT_REGISTRY
    level, reason = classify_port_risk(31337, service="redis-custom")
    assert level == "high"
    assert reason == "Redis in-memory datastore"


def test_get_port_description_fallback_unknown_port():
    """Port 31337 with no service hint must return the generic fallback description."""
    assert 31337 not in PORT_REGISTRY
    desc = get_port_description(31337)
    assert "31337" in desc.purpose
    assert desc.name == "Unknown"


def test_get_port_description_fallback_keyword_match():
    """Port 31337 with service='redis-custom' must match the 'redis' keyword fallback."""
    assert 31337 not in PORT_REGISTRY
    desc = get_port_description(31337, service="redis-custom")
    assert desc.name == "Redis"
    assert "authentication" in desc.security_concern.lower()


def test_classify_port_risk_well_known_port_fallback():
    """A well-known port (e.g. 999) not in the registry uses the well-known fallback."""
    assert 999 not in PORT_REGISTRY
    level, reason = classify_port_risk(999)
    assert level == "medium"
    assert "999" in reason
    assert "well-known" in reason.lower()
