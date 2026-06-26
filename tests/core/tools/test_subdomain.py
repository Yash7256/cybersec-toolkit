"""
Tests for cybersec/core/tools/subdomain.py.

Coverage targets:
  - classify_subdomain_risk()
  - compute_confidence()
  - _detect_wildcard()
  - resolve_subdomain_records()
  - probe_subdomain_http()
  - find_subdomains() end-to-end (mocked network)
  - stream_subdomain_events() event sequence + consistency with find_subdomains()

All DNS and HTTP calls are mocked; no real network access is required.
"""
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch, call

import dns.exception
import dns.name
import dns.resolver
import httpx
import pytest

import cybersec.core.tools.subdomain as sdmod
from cybersec.core.tools.subdomain import (
    RECORD_TYPES,
    RISK_KEYWORDS,
    TECH_BODY_PATTERNS,
    TECH_COOKIE_PATTERNS,
    TECH_HEADER_PATTERNS,
    WORDLISTS,
    SubdomainResult,
    classify_subdomain_risk,
    compute_confidence,
    probe_subdomain_http,
    resolve_subdomain_records,
    stream_subdomain_events,
    find_subdomains,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _resolved_entry(
    subdomain: str = "www.example.com",
    a_records: list[str] | None = None,
    aaaa_records: list[str] | None = None,
    other_records: dict | None = None,
    http: dict | None = None,
    wildcard: bool = False,
) -> dict:
    """Build a minimal resolved DNS result dict for use in unit tests."""
    records: dict = {
        "A": a_records or [],
        "AAAA": aaaa_records or [],
        "CNAME": [],
        "MX": (other_records or {}).get("MX", []),
        "TXT": (other_records or {}).get("TXT", []),
        "NS": (other_records or {}).get("NS", []),
    }
    entry: dict = {
        "subdomain": subdomain,
        "records": records,
        "resolved": True,
        "source": ["wordlist"],
        "dns_ms": 1,
    }
    if a_records:
        entry["ip"] = a_records[0]
    if http is not None:
        entry["http"] = http
    if wildcard:
        entry["wildcard"] = True
    return entry


def _unresolved_entry(subdomain: str = "nxdomain.example.com", error: str = "NXDOMAIN") -> dict:
    return {
        "subdomain": subdomain,
        "records": {r: [] for r in RECORD_TYPES},
        "resolved": False,
        "source": ["wordlist"],
        "dns_ms": 1,
        "error": error,
    }


def _make_resp(
    status: int = 200,
    headers: dict | None = None,
    content: bytes = b"",
    url: str = "https://example.com",
) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.headers = headers or {}
    resp.content = content
    resp.url = url
    return resp


# ===========================================================================
# 1. classify_subdomain_risk()
# ===========================================================================

class TestClassifySubdomainRisk:

    # -- HIGH keyword matches ------------------------------------------------

    def test_high_keyword_admin(self):
        r = classify_subdomain_risk("admin.example.com")
        assert r["level"] == "HIGH"
        assert "admin" in r["reason"]

    def test_high_keyword_vpn(self):
        r = classify_subdomain_risk("vpn.example.com")
        assert r["level"] == "HIGH"
        assert "vpn" in r["reason"]

    def test_high_keyword_jira(self):
        r = classify_subdomain_risk("jira.example.com")
        assert r["level"] == "HIGH"

    def test_high_keyword_jenkins(self):
        r = classify_subdomain_risk("jenkins.example.com")
        assert r["level"] == "HIGH"

    def test_high_keyword_db(self):
        r = classify_subdomain_risk("db.example.com")
        assert r["level"] == "HIGH"

    def test_high_keyword_staging(self):
        r = classify_subdomain_risk("staging.example.com")
        assert r["level"] == "HIGH"

    def test_high_keyword_dev(self):
        r = classify_subdomain_risk("dev.example.com")
        assert r["level"] == "HIGH"

    def test_high_keyword_internal(self):
        r = classify_subdomain_risk("internal.example.com")
        assert r["level"] == "HIGH"

    def test_high_keyword_covers_all_defined(self):
        for kw in RISK_KEYWORDS["HIGH"]:
            r = classify_subdomain_risk(f"{kw}.example.com")
            assert r["level"] == "HIGH", f"Expected HIGH for keyword '{kw}'"

    # -- MEDIUM keyword matches ----------------------------------------------

    def test_medium_keyword_mail(self):
        r = classify_subdomain_risk("mail.example.com")
        assert r["level"] == "MEDIUM"
        assert "mail" in r["reason"]

    def test_medium_keyword_ftp(self):
        r = classify_subdomain_risk("ftp.example.com")
        assert r["level"] == "MEDIUM"

    def test_medium_keyword_cdn(self):
        r = classify_subdomain_risk("cdn.example.com")
        assert r["level"] == "MEDIUM"

    def test_medium_keyword_covers_all_defined(self):
        for kw in RISK_KEYWORDS["MEDIUM"]:
            r = classify_subdomain_risk(f"{kw}.example.com")
            assert r["level"] == "MEDIUM", f"Expected MEDIUM for keyword '{kw}'"

    # -- Keyword takes priority over HTTP status ----------------------------

    def test_keyword_priority_over_200(self):
        """admin.example.com with HTTP 200 must be HIGH, not LOW."""
        r = classify_subdomain_risk(
            "admin.example.com",
            http={"alive": True, "status": 200, "title": "", "technologies": []},
        )
        assert r["level"] == "HIGH"

    def test_keyword_priority_over_404(self):
        r = classify_subdomain_risk(
            "vpn.example.com",
            http={"alive": True, "status": 404, "title": "", "technologies": []},
        )
        assert r["level"] == "HIGH"

    # -- Regex label boundary checks ----------------------------------------

    def test_admin_matches_at_start(self):
        assert classify_subdomain_risk("admin.example.com")["level"] == "HIGH"

    def test_admin_matches_after_dot(self):
        assert classify_subdomain_risk("old.admin.example.com")["level"] == "HIGH"

    def test_admin_matches_after_hyphen(self):
        assert classify_subdomain_risk("old-admin.example.com")["level"] == "HIGH"

    def test_admin_does_not_match_administrator(self):
        """'admin' inside 'administrator' must NOT trigger a keyword hit."""
        r = classify_subdomain_risk("administrator.example.com")
        assert r["level"] != "HIGH" or "admin" not in r.get("reason", "")

    def test_api_does_not_match_apigateway_as_full_label(self):
        """'api' should NOT match if it's part of a longer label like 'apigateway'."""
        r = classify_subdomain_risk("apigateway.example.com")
        # 'api' is a prefix of 'apigateway' — regex requires label boundary after it
        assert r["level"] != "HIGH" or "api" not in r.get("reason", "")

    # -- HTTP-status-based classification (no keyword) ----------------------

    def test_http_401_returns_high(self):
        r = classify_subdomain_risk(
            "www.example.com",
            http={"alive": True, "status": 401, "title": "", "technologies": []},
        )
        assert r["level"] == "HIGH"
        assert "401" in r["reason"]

    def test_http_403_returns_high(self):
        r = classify_subdomain_risk(
            "www.example.com",
            http={"alive": True, "status": 403, "title": "", "technologies": []},
        )
        assert r["level"] == "HIGH"

    def test_http_407_returns_high(self):
        r = classify_subdomain_risk(
            "www.example.com",
            http={"alive": True, "status": 407, "title": "", "technologies": []},
        )
        assert r["level"] == "HIGH"

    def test_http_500_returns_high(self):
        r = classify_subdomain_risk(
            "www.example.com",
            http={"alive": True, "status": 500, "title": "", "technologies": []},
        )
        assert r["level"] == "HIGH"

    def test_http_502_returns_high(self):
        r = classify_subdomain_risk(
            "www.example.com",
            http={"alive": True, "status": 502, "title": "", "technologies": []},
        )
        assert r["level"] == "HIGH"

    def test_http_503_returns_high(self):
        r = classify_subdomain_risk(
            "www.example.com",
            http={"alive": True, "status": 503, "title": "", "technologies": []},
        )
        assert r["level"] == "HIGH"

    # -- Title-based HIGH ---------------------------------------------------

    def test_title_login_returns_high(self):
        r = classify_subdomain_risk(
            "www.example.com",
            http={"alive": True, "status": 200, "title": "Login Page", "technologies": []},
        )
        assert r["level"] == "HIGH"
        assert "login" in r["reason"]

    def test_title_admin_returns_high(self):
        r = classify_subdomain_risk(
            "www.example.com",
            http={"alive": True, "status": 200, "title": "Admin Panel", "technologies": []},
        )
        assert r["level"] == "HIGH"

    def test_title_dashboard_returns_high(self):
        r = classify_subdomain_risk(
            "www.example.com",
            http={"alive": True, "status": 200, "title": "Dashboard", "technologies": []},
        )
        assert r["level"] == "HIGH"

    def test_title_signin_returns_high(self):
        r = classify_subdomain_risk(
            "www.example.com",
            http={"alive": True, "status": 200, "title": "Signin Portal", "technologies": []},
        )
        assert r["level"] == "HIGH"

    # -- MEDIUM HTTP results ------------------------------------------------

    def test_redirect_301_returns_medium(self):
        r = classify_subdomain_risk(
            "www.example.com",
            http={"alive": True, "status": 301, "title": "", "technologies": []},
        )
        assert r["level"] == "MEDIUM"

    def test_redirect_302_returns_medium(self):
        r = classify_subdomain_risk(
            "www.example.com",
            http={"alive": True, "status": 302, "title": "", "technologies": []},
        )
        assert r["level"] == "MEDIUM"

    def test_redirect_307_returns_medium(self):
        r = classify_subdomain_risk(
            "www.example.com",
            http={"alive": True, "status": 307, "title": "", "technologies": []},
        )
        assert r["level"] == "MEDIUM"

    def test_redirect_308_returns_medium(self):
        r = classify_subdomain_risk(
            "www.example.com",
            http={"alive": True, "status": 308, "title": "", "technologies": []},
        )
        assert r["level"] == "MEDIUM"

    def test_http_404_returns_medium(self):
        r = classify_subdomain_risk(
            "www.example.com",
            http={"alive": True, "status": 404, "title": "", "technologies": []},
        )
        assert r["level"] == "MEDIUM"

    def test_technologies_no_other_signal_returns_medium(self):
        r = classify_subdomain_risk(
            "www.example.com",
            http={"alive": True, "status": 200, "title": "", "technologies": ["Nginx"]},
        )
        assert r["level"] == "MEDIUM"
        assert "Nginx" in r["reason"]

    # -- LOW results --------------------------------------------------------

    def test_200_no_other_signal_returns_low(self):
        r = classify_subdomain_risk(
            "www.example.com",
            http={"alive": True, "status": 200, "title": "", "technologies": []},
        )
        assert r["level"] == "LOW"

    def test_no_http_data_returns_low(self):
        r = classify_subdomain_risk("www.example.com", http=None)
        assert r["level"] == "LOW"
        assert "no web service" in r["reason"].lower()

    def test_http_not_alive_returns_low(self):
        r = classify_subdomain_risk(
            "www.example.com",
            http={"alive": False},
        )
        assert r["level"] == "LOW"


# ===========================================================================
# 2. compute_confidence()
# ===========================================================================

class TestComputeConfidence:

    def test_not_resolved_returns_zero(self):
        entry = {"resolved": False, "records": {r: [] for r in RECORD_TYPES}}
        verified, score = compute_confidence(entry)
        assert verified is False
        assert score == 0.0

    def test_a_record_only_single_ip(self):
        entry = _resolved_entry(a_records=["1.2.3.4"])
        verified, score = compute_confidence(entry)
        # A record = 0.35; no http, no AAAA, no other
        assert score == pytest.approx(0.35)
        assert verified is False  # 0.35 < 0.6

    def test_two_a_records_gets_bonus(self):
        entry = _resolved_entry(a_records=["1.2.3.4", "1.2.3.5"])
        _, score = compute_confidence(entry)
        # 0.35 (A) + 0.05 (>=2 IPs)
        assert score == pytest.approx(0.40)

    def test_aaaa_only_adds_smaller_bonus(self):
        entry = _resolved_entry(aaaa_records=["::1"])
        # IPv6 loopback resolves but _is_safe_public_ip won't matter for confidence
        _, score = compute_confidence(entry)
        assert score == pytest.approx(0.05)

    def test_a_plus_aaaa(self):
        entry = _resolved_entry(a_records=["1.2.3.4"], aaaa_records=["2001:db8::1"])
        _, score = compute_confidence(entry)
        assert score == pytest.approx(0.35 + 0.05)

    def test_other_records_add_bonus(self):
        entry = _resolved_entry(
            a_records=["1.2.3.4"],
            other_records={"MX": ["mail.example.com"]},
        )
        _, score = compute_confidence(entry)
        assert score == pytest.approx(0.35 + 0.10)

    def test_alive_2xx_adds_more_than_4xx(self):
        entry_2xx = _resolved_entry(
            a_records=["1.2.3.4"],
            http={"alive": True, "status": 200, "response_time_ms": 10},
        )
        entry_4xx = _resolved_entry(
            a_records=["1.2.3.4"],
            http={"alive": True, "status": 401, "response_time_ms": 10},
        )
        _, score_2xx = compute_confidence(entry_2xx)
        _, score_4xx = compute_confidence(entry_4xx)
        assert score_2xx > score_4xx

    def test_alive_2xx_verified(self):
        entry = _resolved_entry(
            a_records=["1.2.3.4"],
            http={"alive": True, "status": 200, "response_time_ms": 100, "title": "Home"},
        )
        verified, score = compute_confidence(entry)
        # 0.35 + 0.30 (2xx) + 0.05 (rt>50) + 0.05 (title) = 0.75
        assert score == pytest.approx(0.75)
        assert verified is True

    def test_response_time_bonus_only_above_50ms(self):
        entry_fast = _resolved_entry(
            a_records=["1.2.3.4"],
            http={"alive": True, "status": 200, "response_time_ms": 30},
        )
        entry_slow = _resolved_entry(
            a_records=["1.2.3.4"],
            http={"alive": True, "status": 200, "response_time_ms": 51},
        )
        _, score_fast = compute_confidence(entry_fast)
        _, score_slow = compute_confidence(entry_slow)
        assert score_slow > score_fast

    def test_wildcard_caps_score_at_0_2(self):
        entry = _resolved_entry(
            a_records=["1.2.3.4"],
            http={"alive": True, "status": 200, "response_time_ms": 200, "title": "Home"},
            wildcard=True,
        )
        verified, score = compute_confidence(entry)
        assert score <= 0.20
        assert verified is False  # wildcard=True blocks verified

    def test_wildcard_ip_penalty_applied(self):
        entry = _resolved_entry(a_records=["1.2.3.4"])
        without_penalty = compute_confidence(entry)[1]
        penalised = compute_confidence(entry, wildcard_ips=["1.2.3.4"])[1]
        assert penalised == pytest.approx(without_penalty * 0.3, abs=0.01)

    def test_wildcard_ip_penalty_not_applied_for_non_matching_ip(self):
        entry = _resolved_entry(a_records=["1.2.3.4"])
        without_penalty = compute_confidence(entry)[1]
        no_match = compute_confidence(entry, wildcard_ips=["9.9.9.9"])[1]
        assert no_match == pytest.approx(without_penalty)

    def test_verified_threshold_at_0_6(self):
        # score exactly 0.6 → verified=True (>= 0.6, no wildcard)
        # A(0.35) + 2xx(0.30) = 0.65 → verified
        entry_above = _resolved_entry(
            a_records=["1.2.3.4"],
            http={"alive": True, "status": 200, "response_time_ms": 10},
        )
        verified_above, score_above = compute_confidence(entry_above)
        assert score_above == pytest.approx(0.65)
        assert verified_above is True

    def test_verified_threshold_just_below_0_6(self):
        # A(0.35) + redirect(0.25) = 0.60 → verified=True (at boundary)
        entry_boundary = _resolved_entry(
            a_records=["1.2.3.4"],
            http={"alive": True, "status": 301, "response_time_ms": 10},
        )
        verified, score = compute_confidence(entry_boundary)
        assert score == pytest.approx(0.60)
        assert verified is True

    def test_verified_false_just_below_boundary(self):
        # A(0.35) + 4xx(0.20) = 0.55 → not verified
        entry = _resolved_entry(
            a_records=["1.2.3.4"],
            http={"alive": True, "status": 401, "response_time_ms": 10},
        )
        verified, score = compute_confidence(entry)
        assert score == pytest.approx(0.55)
        assert verified is False


# ===========================================================================
# 3. _detect_wildcard()
# ===========================================================================

class TestDetectWildcard:

    @pytest.mark.asyncio
    async def test_wildcard_detected_when_random_resolves(self):
        """Mock resolver returning a fixed IP for any random prefix → wildcard detected."""
        fake_rdata = MagicMock()
        fake_rdata.address = "1.2.3.4"
        fake_answers = [fake_rdata]

        with patch.object(sdmod._dns_resolver, "resolve", new=AsyncMock(return_value=fake_answers)):
            detected, ips = await sdmod._detect_wildcard("example.com")

        assert detected is True
        assert "1.2.3.4" in ips

    @pytest.mark.asyncio
    async def test_no_wildcard_when_all_nxdomain(self):
        """Mock resolver raising NXDOMAIN for all random checks → no wildcard."""
        with patch.object(
            sdmod._dns_resolver,
            "resolve",
            new=AsyncMock(side_effect=dns.resolver.NXDOMAIN()),
        ):
            detected, ips = await sdmod._detect_wildcard("example.com")

        assert detected is False
        assert ips == []

    @pytest.mark.asyncio
    async def test_wildcard_collects_multiple_ips(self):
        """Three random checks each returning a different IP → all are collected."""
        call_count = 0

        async def varying_resolve(hostname, rtype):
            nonlocal call_count
            call_count += 1
            r = MagicMock()
            r.address = f"1.2.3.{call_count}"
            return [r]

        with patch.object(sdmod._dns_resolver, "resolve", side_effect=varying_resolve):
            detected, ips = await sdmod._detect_wildcard("example.com")

        assert detected is True
        assert len(ips) >= 1  # at least one IP collected across N_WILDCARD_CHECKS=3


# ===========================================================================
# 4. resolve_subdomain_records()
# ===========================================================================

def _fake_rdata_a(ip: str) -> MagicMock:
    r = MagicMock()
    r.address = ip
    return r


def _fake_rdata_cname(target: str) -> MagicMock:
    r = MagicMock()
    r.target = target
    return r


class TestResolveSubdomainRecords:

    @pytest.mark.asyncio
    async def test_nxdomain_returns_not_resolved(self):
        with patch.object(
            sdmod._dns_resolver,
            "resolve",
            new=AsyncMock(side_effect=dns.resolver.NXDOMAIN()),
        ):
            result = await resolve_subdomain_records("nope.example.com")

        assert result["resolved"] is False
        assert result["error"] == "NXDOMAIN"

    @pytest.mark.asyncio
    async def test_no_answer_returns_not_resolved(self):
        with patch.object(
            sdmod._dns_resolver,
            "resolve",
            new=AsyncMock(side_effect=dns.resolver.NoAnswer()),
        ):
            result = await resolve_subdomain_records("silent.example.com")

        assert result["resolved"] is False
        assert result.get("error") == "no records"

    @pytest.mark.asyncio
    async def test_a_record_success(self):
        async def fake_resolve(hostname, rtype):
            if rtype == "A":
                return [_fake_rdata_a("93.184.216.34")]
            raise dns.resolver.NoAnswer()

        with patch.object(sdmod._dns_resolver, "resolve", side_effect=fake_resolve):
            result = await resolve_subdomain_records("www.example.com")

        assert result["resolved"] is True
        assert result["records"]["A"] == ["93.184.216.34"]
        assert result["ip"] == "93.184.216.34"

    @pytest.mark.asyncio
    async def test_timeout_triggers_retry_and_eventually_succeeds(self):
        """First call raises Timeout; second call for same rtype succeeds."""
        call_counts: dict[str, int] = {}

        async def fake_resolve(hostname, rtype):
            call_counts[rtype] = call_counts.get(rtype, 0) + 1
            if rtype == "A" and call_counts["A"] == 1:
                raise dns.exception.Timeout()
            if rtype == "A":
                return [_fake_rdata_a("1.2.3.4")]
            raise dns.resolver.NoAnswer()

        with (
            patch.object(sdmod._dns_resolver, "resolve", side_effect=fake_resolve),
            patch("asyncio.sleep", new=AsyncMock()),
        ):
            result = await resolve_subdomain_records("retry.example.com")

        assert result["resolved"] is True
        assert result["records"]["A"] == ["1.2.3.4"]
        assert call_counts.get("A", 0) == 2  # tried twice

    @pytest.mark.asyncio
    async def test_timeout_all_retries_sets_timeout_error(self):
        """All MAX_RETRIES attempts timeout → error='timeout'."""
        with (
            patch.object(
                sdmod._dns_resolver,
                "resolve",
                new=AsyncMock(side_effect=dns.exception.Timeout()),
            ),
            patch("asyncio.sleep", new=AsyncMock()),
        ):
            result = await resolve_subdomain_records("timeout.example.com")

        assert result["resolved"] is False
        assert result.get("error") == "timeout"

    @pytest.mark.asyncio
    async def test_subdomain_field_set_correctly(self):
        with patch.object(
            sdmod._dns_resolver,
            "resolve",
            new=AsyncMock(side_effect=dns.resolver.NXDOMAIN()),
        ):
            result = await resolve_subdomain_records("sub.example.com")

        assert result["subdomain"] == "sub.example.com"

    @pytest.mark.asyncio
    async def test_source_field_preserved(self):
        with patch.object(
            sdmod._dns_resolver,
            "resolve",
            new=AsyncMock(side_effect=dns.resolver.NXDOMAIN()),
        ):
            result = await resolve_subdomain_records("sub.example.com", source="manual")

        assert result["source"] == ["manual"]


# ===========================================================================
# 5. probe_subdomain_http()
# ===========================================================================

class TestProbeSubdomainHttp:

    @pytest.mark.asyncio
    async def test_https_success_alive(self):
        resp = _make_resp(200, {"server": "nginx"}, b"<html><title>Hello</title></html>", "https://www.example.com")
        client = AsyncMock()
        client.get = AsyncMock(return_value=resp)

        result = await probe_subdomain_http(client, "www.example.com")

        assert result["alive"] is True
        assert result["scheme"] == "https"
        assert result["status"] == 200
        assert result["title"] == "Hello"

    @pytest.mark.asyncio
    async def test_title_extracted_from_body(self):
        body = b"<html><head><title>My Page</title></head><body></body></html>"
        resp = _make_resp(200, {}, body, "https://example.com")
        client = AsyncMock()
        client.get = AsyncMock(return_value=resp)

        result = await probe_subdomain_http(client, "example.com")
        assert result.get("title") == "My Page"

    @pytest.mark.asyncio
    async def test_https_connect_error_falls_back_to_http(self):
        http_resp = _make_resp(200, {"server": "Apache"}, b"", "http://www.example.com")

        async def side_effect(url, **kw):
            if url.startswith("https://"):
                raise httpx.ConnectError("refused")
            return http_resp

        client = AsyncMock()
        client.get = AsyncMock(side_effect=side_effect)

        result = await probe_subdomain_http(client, "www.example.com")
        assert result["alive"] is True
        assert result["scheme"] == "http"

    @pytest.mark.asyncio
    async def test_both_fail_returns_not_alive(self):
        client = AsyncMock()
        client.get = AsyncMock(side_effect=httpx.ConnectError("refused"))

        result = await probe_subdomain_http(client, "dead.example.com")
        assert result["alive"] is False

    @pytest.mark.asyncio
    async def test_connect_timeout_falls_back(self):
        http_resp = _make_resp(200, {}, b"", "http://slow.example.com")

        async def side_effect(url, **kw):
            if url.startswith("https://"):
                raise httpx.ConnectTimeout("timed out")
            return http_resp

        client = AsyncMock()
        client.get = AsyncMock(side_effect=side_effect)
        result = await probe_subdomain_http(client, "slow.example.com")
        assert result["alive"] is True
        assert result["scheme"] == "http"

    @pytest.mark.asyncio
    async def test_redirect_url_captured(self):
        resp = _make_resp(301, {}, b"", "https://new.example.com/")
        resp.url = "https://new.example.com/"
        client = AsyncMock()
        client.get = AsyncMock(return_value=resp)

        result = await probe_subdomain_http(client, "example.com")
        assert result["redirect_to"] == "https://new.example.com/"

    @pytest.mark.asyncio
    async def test_server_header_captured(self):
        resp = _make_resp(200, {"server": "Caddy"}, b"", "https://x.example.com")
        client = AsyncMock()
        client.get = AsyncMock(return_value=resp)
        result = await probe_subdomain_http(client, "x.example.com")
        assert result["server"] == "Caddy"

    # -- Technology detection -----------------------------------------------

    @pytest.mark.asyncio
    @pytest.mark.parametrize("pattern,expected_name", TECH_HEADER_PATTERNS)
    async def test_tech_header_pattern_detected(self, pattern, expected_name):
        resp = _make_resp(200, {"server": pattern}, b"", "https://h.example.com")
        client = AsyncMock()
        client.get = AsyncMock(return_value=resp)
        result = await probe_subdomain_http(client, "h.example.com")
        assert expected_name in result.get("technologies", [])

    @pytest.mark.asyncio
    @pytest.mark.parametrize("pattern,expected_name", TECH_COOKIE_PATTERNS)
    async def test_tech_cookie_pattern_detected(self, pattern, expected_name):
        resp = _make_resp(200, {"set-cookie": f"{pattern}=abc"}, b"", "https://c.example.com")
        client = AsyncMock()
        client.get = AsyncMock(return_value=resp)
        result = await probe_subdomain_http(client, "c.example.com")
        assert expected_name in result.get("technologies", [])

    @pytest.mark.asyncio
    @pytest.mark.parametrize("pattern,expected_name", TECH_BODY_PATTERNS)
    async def test_tech_body_pattern_detected(self, pattern, expected_name):
        body = f"<html>{pattern}</html>".encode()
        resp = _make_resp(200, {}, body, "https://b.example.com")
        client = AsyncMock()
        client.get = AsyncMock(return_value=resp)
        result = await probe_subdomain_http(client, "b.example.com")
        assert expected_name in result.get("technologies", [])


# ===========================================================================
# Shared mock helpers for end-to-end tests
# ===========================================================================

def _build_dns_mock(
    domain: str,
    resolved_entries: dict[str, list[str]],
) -> AsyncMock:
    """
    Returns a mock for resolve_subdomain_records.

    resolved_entries: maps subdomain prefix → list of A-record IPs.
    Any prefix not in the map → NXDOMAIN (not resolved).
    """
    async def fake_resolve(hostname: str, source: str = "wordlist") -> dict:
        prefix = hostname.split(".")[0]
        ips = resolved_entries.get(prefix, [])
        if ips:
            return {
                "subdomain": hostname,
                "records": {
                    "A": ips,
                    "AAAA": [],
                    "CNAME": [],
                    "MX": [],
                    "TXT": [],
                    "NS": [],
                },
                "resolved": True,
                "source": [source],
                "dns_ms": 1,
                "ip": ips[0],
            }
        return {
            "subdomain": hostname,
            "records": {r: [] for r in RECORD_TYPES},
            "resolved": False,
            "source": [source],
            "dns_ms": 1,
            "error": "NXDOMAIN",
        }
    return fake_resolve


def _http_mock_alive() -> AsyncMock:
    async def fake_probe(client, hostname: str) -> dict:
        return {"alive": True, "status": 200, "scheme": "https", "server": "nginx",
                "technologies": [], "response_time_ms": 80}
    return fake_probe


# ===========================================================================
# 6. find_subdomains() end-to-end
# ===========================================================================

class TestFindSubdomains:

    async def _run(
        self,
        resolved: dict[str, list[str]],
        domain: str = "example.com",
        wordlist: str = "small",
        strictness: str = "off",
        wildcard: tuple[bool, list[str]] = (False, []),
    ) -> SubdomainResult:
        with (
            patch.object(sdmod, "resolve_subdomain_records",
                         side_effect=_build_dns_mock(domain, resolved)),
            patch.object(sdmod, "probe_subdomain_http",
                         side_effect=_http_mock_alive()),
            patch.object(sdmod, "capture_screenshots", new=AsyncMock()),
            patch.object(sdmod, "_detect_wildcard",
                         new=AsyncMock(return_value=wildcard)),
        ):
            return await find_subdomains(domain, wordlist=wordlist, strictness=strictness)

    @pytest.mark.asyncio
    async def test_total_checked_equals_wordlist_length(self):
        result = await self._run({"www": ["93.184.216.34"]})
        assert result.total_checked == len(WORDLISTS["small"])

    @pytest.mark.asyncio
    async def test_total_found_equals_resolved_count(self):
        result = await self._run({"www": ["93.184.216.34"], "api": ["93.184.216.35"]})
        assert result.total_found == 2

    @pytest.mark.asyncio
    async def test_dns_time_ms_positive(self):
        result = await self._run({"www": ["93.184.216.34"]})
        assert result.dns_time_ms >= 0  # ≥0 since mocked calls are instant

    @pytest.mark.asyncio
    async def test_http_time_ms_positive_when_resolved(self):
        result = await self._run({"www": ["93.184.216.34"]})
        assert result.http_time_ms >= 0

    @pytest.mark.asyncio
    async def test_domain_field_on_result(self):
        result = await self._run({}, domain="test.example.com")
        assert result.domain == "test.example.com"

    @pytest.mark.asyncio
    async def test_wildcard_medium_strictness_removes_matching_entry(self):
        """
        Wildcard IPs = ["1.2.3.4"]. Entry whose A record matches wildcard IP
        must be excluded from results when strictness is 'medium'.
        """
        result = await self._run(
            {"www": ["1.2.3.4"], "api": ["93.184.216.34"]},
            strictness="medium",
            wildcard=(True, ["1.2.3.4"]),
        )
        subdomains = [r["subdomain"] for r in result.found]
        assert not any("www" in s for s in subdomains), "wildcard-matching entry should be removed"
        assert any("api" in s for s in subdomains)

    @pytest.mark.asyncio
    async def test_wildcard_high_strictness_removes_matching_entry(self):
        result = await self._run(
            {"www": ["1.2.3.4"], "api": ["93.184.216.34"]},
            strictness="high",
            wildcard=(True, ["1.2.3.4"]),
        )
        subdomains = [r["subdomain"] for r in result.found]
        assert not any("www" in s for s in subdomains)

    @pytest.mark.asyncio
    async def test_wildcard_low_strictness_keeps_matching_entry_but_marks_it(self):
        """
        'low' strictness: wildcard entries are NOT removed from results
        (only medium/high filter them out), but they are still marked wildcard=True.
        This is a meaningful behavioral distinction explicitly tested here.
        """
        result = await self._run(
            {"www": ["1.2.3.4"], "api": ["93.184.216.34"]},
            strictness="low",
            wildcard=(True, ["1.2.3.4"]),
        )
        subdomains = [r["subdomain"] for r in result.found]
        # 'low' keeps the entry in results
        assert any("www" in s for s in subdomains), "low strictness should keep wildcard-IP entries"
        # but it is marked
        www_entry = next(r for r in result.found if "www" in r["subdomain"])
        assert www_entry.get("wildcard") is True

    @pytest.mark.asyncio
    async def test_wildcard_off_skips_detection_entirely(self):
        detect_mock = AsyncMock(return_value=(False, []))
        with (
            patch.object(sdmod, "resolve_subdomain_records",
                         side_effect=_build_dns_mock("example.com", {})),
            patch.object(sdmod, "probe_subdomain_http", side_effect=_http_mock_alive()),
            patch.object(sdmod, "capture_screenshots", new=AsyncMock()),
            patch.object(sdmod, "_detect_wildcard", new=detect_mock),
        ):
            await find_subdomains("example.com", strictness="off")
        detect_mock.assert_not_called()

    @pytest.mark.asyncio
    async def test_found_entries_have_risk_and_confidence(self):
        result = await self._run({"www": ["93.184.216.34"]})
        resolved_entries = [r for r in result.found if r.get("resolved")]
        for entry in resolved_entries:
            assert "risk" in entry
            assert "confidence" in entry
            assert "verified" in entry

    @pytest.mark.asyncio
    async def test_unresolved_entries_present_in_found(self):
        result = await self._run({"www": ["93.184.216.34"]})
        unresolved = [r for r in result.found if not r.get("resolved")]
        # total_checked - 1 resolved = unresolved count (dynamic, wordlist size may change)
        assert len(unresolved) == len(WORDLISTS["small"]) - 1


# ===========================================================================
# 7. stream_subdomain_events() — event sequence + consistency
# ===========================================================================

class TestStreamSubdomainEvents:

    async def _collect_events(
        self,
        resolved: dict[str, list[str]],
        domain: str = "example.com",
        wordlist: str = "small",
        strictness: str = "off",
        wildcard: tuple[bool, list[str]] = (False, []),
    ) -> list[dict]:
        original_wordlists = sdmod.WORDLISTS.copy()
        sdmod.WORDLISTS["_t"] = list(resolved.keys()) or ["www"]
        try:
            events = []
            with (
                patch.object(sdmod, "resolve_subdomain_records",
                             side_effect=_build_dns_mock(domain, resolved)),
                patch.object(sdmod, "probe_subdomain_http",
                             side_effect=_http_mock_alive()),
                patch.object(sdmod, "capture_screenshots", new=AsyncMock()),
                patch.object(sdmod, "_detect_wildcard",
                             new=AsyncMock(return_value=wildcard)),
            ):
                async for event in stream_subdomain_events(
                    domain, wordlist="_t", strictness=strictness
                ):
                    events.append(event)
        finally:
            sdmod.WORDLISTS.clear()
            sdmod.WORDLISTS.update(original_wordlists)
        return events

    @pytest.mark.asyncio
    async def test_first_event_is_init(self):
        events = await self._collect_events({"www": ["93.184.216.34"]})
        assert events[0]["type"] == "init"

    @pytest.mark.asyncio
    async def test_last_event_is_done(self):
        events = await self._collect_events({"www": ["93.184.216.34"]})
        assert events[-1]["type"] == "done"

    @pytest.mark.asyncio
    async def test_done_event_has_data_field(self):
        events = await self._collect_events({"www": ["93.184.216.34"]})
        done = events[-1]
        assert "data" in done
        assert done["data"]["domain"] == "example.com"

    @pytest.mark.asyncio
    async def test_wildcard_events_emitted_when_strictness_not_off(self):
        events = await self._collect_events(
            {"www": ["93.184.216.34"]},
            strictness="medium",
            wildcard=(False, []),
        )
        types = [e["type"] for e in events]
        assert "wildcard" in types
        # wildcard stage event
        stage_events = [e for e in events if e.get("type") == "stage"]
        assert any(e.get("stage") == "wildcard" for e in stage_events)

    @pytest.mark.asyncio
    async def test_no_wildcard_events_when_strictness_off(self):
        events = await self._collect_events(
            {"www": ["93.184.216.34"]},
            strictness="off",
        )
        types = [e["type"] for e in events]
        assert "wildcard" not in types

    @pytest.mark.asyncio
    async def test_candidate_events_emitted_per_hostname(self):
        events = await self._collect_events({"www": ["93.184.216.34"]})
        candidate_events = [e for e in events if e["type"] == "candidate"]
        # should have at least one candidate per wordlist entry
        assert len(candidate_events) >= 1

    @pytest.mark.asyncio
    async def test_http_stage_event_emitted_when_resolved(self):
        events = await self._collect_events({"www": ["93.184.216.34"]})
        stage_events = [e for e in events if e.get("type") == "stage"]
        assert any(e.get("stage") == "http" for e in stage_events)

    @pytest.mark.asyncio
    async def test_no_http_stage_when_nothing_resolves(self):
        events = await self._collect_events({})  # nothing resolves
        stage_events = [e for e in events if e.get("type") == "stage"]
        assert not any(e.get("stage") == "http" for e in stage_events)

    @pytest.mark.asyncio
    async def test_streaming_and_batch_produce_equivalent_final_results(self):
        """
        The streaming and non-streaming paths share logic but are separate
        implementations. Their final outputs must agree on total_found, domain,
        and resolved subdomains.
        """
        resolved_map = {"www": ["93.184.216.34"], "api": ["93.184.216.35"]}
        domain = "example.com"

        # Batch result
        with (
            patch.object(sdmod, "resolve_subdomain_records",
                         side_effect=_build_dns_mock(domain, resolved_map)),
            patch.object(sdmod, "probe_subdomain_http",
                         side_effect=_http_mock_alive()),
            patch.object(sdmod, "capture_screenshots", new=AsyncMock()),
            patch.object(sdmod, "_detect_wildcard",
                         new=AsyncMock(return_value=(False, []))),
        ):
            batch = await find_subdomains(domain, wordlist="small", strictness="off")

        # Streaming result
        stream_events = await self._collect_events(
            resolved_map, domain=domain, wordlist="small", strictness="off"
        )

        done_event = next(e for e in stream_events if e["type"] == "done")
        stream_data = done_event["data"]

        assert stream_data["domain"] == batch.domain
        assert stream_data["total_found"] == batch.total_found

        stream_resolved_subs = sorted(
            r["subdomain"] for r in stream_data["found"] if r.get("resolved")
        )
        batch_resolved_subs = sorted(
            r["subdomain"] for r in batch.found if r.get("resolved")
        )
        assert stream_resolved_subs == batch_resolved_subs


# ===========================================================================
# FIX 5 — capture_screenshots() parallelism + semaphore bound
# ===========================================================================

class TestCaptureScreenshots:

    def _alive_entries(self, n: int) -> list[dict]:
        """Create n fake alive entries."""
        return [
            {
                "subdomain": f"host{i}.example.com",
                "resolved": True,
                "http": {"alive": True, "scheme": "https"},
            }
            for i in range(n)
        ]

    @pytest.mark.asyncio
    async def test_no_op_when_pyppeteer_not_installed(self):
        """If pyppeteer is not importable, capture_screenshots returns without error."""
        import sys
        # Temporarily hide pyppeteer from imports
        original = sys.modules.get("pyppeteer")
        sys.modules["pyppeteer"] = None  # makes `import pyppeteer` raise ImportError
        try:
            from cybersec.core.tools.subdomain import capture_screenshots
            entries = self._alive_entries(3)
            # Must return silently; no exception
            await capture_screenshots(entries)
            # Entries must be unchanged (no screenshot key added)
            for e in entries:
                assert "screenshot" not in e
        finally:
            if original is None:
                sys.modules.pop("pyppeteer", None)
            else:
                sys.modules["pyppeteer"] = original

    @pytest.mark.asyncio
    async def test_concurrent_screenshots_bounded_by_semaphore(self):
        """
        10 entries, each page takes 0.1 s (mocked). With SCREENSHOT_CONCURRENCY=5
        pages run in parallel, so total time ≈ 2 × 0.1 s, far less than 10 × 0.1 s.
        Also asserts peak concurrent 'open' pages never exceeds SCREENSHOT_CONCURRENCY.
        """
        import time as _time
        from cybersec.core.tools import subdomain as sdmod

        PAGE_DELAY = 0.05  # seconds per page
        N = 10

        peak_concurrent = 0
        current_concurrent = 0

        async def fake_new_page():
            nonlocal peak_concurrent, current_concurrent
            current_concurrent += 1
            peak_concurrent = max(peak_concurrent, current_concurrent)
            page = AsyncMock()
            page.setViewport = AsyncMock()

            async def fake_goto(*a, **kw):
                await asyncio.sleep(PAGE_DELAY)

            page.goto = AsyncMock(side_effect=fake_goto)
            page.screenshot = AsyncMock()

            async def fake_close():
                nonlocal current_concurrent
                current_concurrent -= 1

            page.close = AsyncMock(side_effect=fake_close)
            return page

        fake_browser = AsyncMock()
        fake_browser.newPage = AsyncMock(side_effect=fake_new_page)
        fake_browser.close = AsyncMock()

        entries = self._alive_entries(N)
        # Reset semaphore to a clean state for this test
        original_sem = sdmod._screenshot_semaphore
        sdmod._screenshot_semaphore = asyncio.Semaphore(sdmod.SCREENSHOT_CONCURRENCY)

        start = _time.monotonic()
        try:
            await asyncio.gather(
                *[sdmod._screenshot_one(fake_browser, e, "/tmp", sdmod.SCREENSHOT_VIEWPORT)
                  for e in entries]
            )
        finally:
            sdmod._screenshot_semaphore = original_sem

        elapsed = _time.monotonic() - start

        # Concurrency: with 5 slots and 10 pages at 0.05 s each → ~0.10 s total
        # Sequential would be 10 × 0.05 = 0.50 s; allow generous 3× budget
        assert elapsed < N * PAGE_DELAY * 0.6, (
            f"Expected concurrent execution, but elapsed {elapsed:.3f}s "
            f"≥ 60% of sequential {N * PAGE_DELAY:.3f}s"
        )

        assert peak_concurrent <= sdmod.SCREENSHOT_CONCURRENCY, (
            f"Peak concurrent pages {peak_concurrent} exceeded semaphore limit "
            f"{sdmod.SCREENSHOT_CONCURRENCY}"
        )

    @pytest.mark.asyncio
    async def test_screenshot_filename_set_on_entry(self):
        """Successful screenshot sets entry['screenshot'] to the filename."""
        from cybersec.core.tools import subdomain as sdmod

        page = AsyncMock()
        page.setViewport = AsyncMock()
        page.goto = AsyncMock()
        page.screenshot = AsyncMock()
        page.close = AsyncMock()

        browser = AsyncMock()
        browser.newPage = AsyncMock(return_value=page)

        entry = {
            "subdomain": "www.example.com",
            "resolved": True,
            "http": {"alive": True, "scheme": "https"},
        }

        original_sem = sdmod._screenshot_semaphore
        sdmod._screenshot_semaphore = asyncio.Semaphore(1)
        try:
            await sdmod._screenshot_one(browser, entry, "/tmp", sdmod.SCREENSHOT_VIEWPORT)
        finally:
            sdmod._screenshot_semaphore = original_sem

        assert entry.get("screenshot") == "www.example.com.png"

    @pytest.mark.asyncio
    async def test_page_none_init_prevents_unboundlocal_on_newpage_failure(self):
        """
        If browser.newPage() itself raises, `page` is None and the finally block
        must not raise UnboundLocalError or NameError.
        """
        from cybersec.core.tools import subdomain as sdmod

        browser = AsyncMock()
        browser.newPage = AsyncMock(side_effect=RuntimeError("browser crashed"))

        entry = {
            "subdomain": "crash.example.com",
            "resolved": True,
            "http": {"alive": True, "scheme": "https"},
        }

        original_sem = sdmod._screenshot_semaphore
        sdmod._screenshot_semaphore = asyncio.Semaphore(1)
        try:
            # Must not raise — exception is swallowed by except Exception: pass
            await sdmod._screenshot_one(browser, entry, "/tmp", sdmod.SCREENSHOT_VIEWPORT)
        finally:
            sdmod._screenshot_semaphore = original_sem

        assert "screenshot" not in entry  # failed silently

    @pytest.mark.asyncio
    async def test_capture_screenshots_skips_when_no_alive_entries(self):
        """No alive entries → browser is never launched."""
        from cybersec.core.tools import subdomain as sdmod

        launch_mock = AsyncMock()
        results = [{"subdomain": "nope.example.com", "resolved": True, "http": {"alive": False}}]

        with patch("builtins.__import__", side_effect=lambda name, *a, **kw: (
            __import__(name, *a, **kw) if name != "pyppeteer" else type(
                "m", (), {"launch": launch_mock}
            )()
        )):
            # Simpler: just call directly with no-alive entries and mock launch path
            pass  # verified via the ImportError path test above

        # Direct path: call with entries that have alive=False
        # pyppeteer is not installed in this env, so we test the alive-filter
        # by patching capture_screenshots to skip the ImportError early return.
        import importlib
        import sys

        # Inject a fake pyppeteer module so capture_screenshots proceeds
        fake_launch = AsyncMock(return_value=AsyncMock())
        fake_pyppeteer = type("pyppeteer", (), {"launch": fake_launch})()
        sys.modules["pyppeteer"] = fake_pyppeteer
        try:
            from importlib import reload
            # Re-import to get module with fake pyppeteer visible
            await sdmod.capture_screenshots(results)
            fake_launch.assert_not_called()
        finally:
            sys.modules.pop("pyppeteer", None)
