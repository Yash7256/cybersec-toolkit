from datetime import datetime, timedelta, timezone

from cybersec.core.tools import whois


def test_normalize_target_strips_scheme_path_and_port():
    assert whois._normalize_target("https://Example.COM:443/login") == "example.com"


def test_status_explanations_normalize_links_and_case():
    explained = whois._status_explanations(["clientTransferProhibited https://icann.org/epp#clientTransferProhibited"])

    assert explained[0]["meaning"] == "Domain transfer is locked by the registrar."


def test_privacy_detection_across_fields():
    assert whois._privacy_detected("Registrant Organization: Domains By Proxy, LLC") is True


def test_risk_indicators_cover_requested_signals():
    now = datetime.now(timezone.utc)
    risks = whois._risk_indicators(
        creation=now - timedelta(days=3),
        updated=now - timedelta(days=2),
        expiry_status="expiring_soon",
        privacy_protected=True,
        statuses=["clientHold"],
        tld="zip",
        now=now,
    )

    ids = {risk["id"] for risk in risks}
    assert "newly_registered" in ids
    assert "expiring_soon" in ids
    assert "privacy_protected" in ids
    assert "recently_updated" in ids
    assert "suspicious_status" in ids
    assert "unusual_tld" in ids


def test_iana_metadata_includes_registry_hint_and_link():
    data = whois._iana_metadata("org", "Public Interest Registry")

    assert data["iana_url"] == "https://www.iana.org/domains/root/db/org.html"
    assert data["registry_hint"] == "Public Interest Registry"
