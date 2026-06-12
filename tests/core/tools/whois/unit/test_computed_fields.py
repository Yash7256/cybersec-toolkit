"""domain_age_days, days_until_expiry, expiry_status logic"""
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from cybersec.core.tools import whois


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _run_lookup(domain, whois_return, rdap_return):
    with patch("cybersec.core.tools.whois.python_whois.whois", return_value=whois_return), \
         patch("cybersec.core.tools.whois._fetch_rdap", return_value=rdap_return), \
         patch("cybersec.core.tools.whois._get_redis", return_value=None):
        return await whois.whois_lookup(domain)


# ======================================================================
# Direct helper-function tests (deterministic – no datetime mocking)
# ======================================================================


class TestExpiryStatusDirect:
    """Test ``_expiry_status()`` pure function directly."""

    _NOW = datetime(2024, 6, 15, 12, 0, 0, tzinfo=timezone.utc)

    def test_expired(self):
        expiry = self._NOW - timedelta(days=1)
        assert whois._expiry_status(expiry, self._NOW) == "expired"

    def test_expired_long_ago(self):
        expiry = self._NOW - timedelta(days=365)
        assert whois._expiry_status(expiry, self._NOW) == "expired"

    def test_expiring_soon_1_day(self):
        expiry = self._NOW + timedelta(days=1)
        assert whois._expiry_status(expiry, self._NOW) == "expiring_soon"

    def test_expiring_soon_30_days(self):
        """Boundary: exactly 30 days → expiring_soon."""
        expiry = self._NOW + timedelta(days=30)
        assert whois._expiry_status(expiry, self._NOW) == "expiring_soon"

    def test_healthy_31_days(self):
        """Boundary: 31 days → healthy."""
        expiry = self._NOW + timedelta(days=31)
        assert whois._expiry_status(expiry, self._NOW) == "healthy"

    def test_healthy_365_days(self):
        expiry = self._NOW + timedelta(days=365)
        assert whois._expiry_status(expiry, self._NOW) == "healthy"

    def test_expires_today(self):
        """Same day: 0 days difference → expiring_soon (days <= 30)."""
        assert whois._expiry_status(self._NOW, self._NOW) == "expiring_soon"

    def test_none_returns_none(self):
        assert whois._expiry_status(None, self._NOW) is None


class TestDaysBetweenDirect:
    """Test ``_days_between()`` pure function directly."""

    def test_positive_days(self):
        start = datetime(2024, 1, 1, tzinfo=timezone.utc)
        end = datetime(2024, 6, 15, tzinfo=timezone.utc)
        result = whois._days_between(start, end)
        assert result == 166

    def test_negative_days(self):
        start = datetime(2024, 6, 15, tzinfo=timezone.utc)
        end = datetime(2024, 1, 1, tzinfo=timezone.utc)
        result = whois._days_between(start, end)
        assert result == -166

    def test_zero_days(self):
        dt = datetime(2024, 6, 15, tzinfo=timezone.utc)
        assert whois._days_between(dt, dt) == 0

    def test_none_start(self):
        assert whois._days_between(None, datetime(2024, 1, 1, tzinfo=timezone.utc)) is None

    def test_none_end(self):
        assert whois._days_between(datetime(2024, 1, 1, tzinfo=timezone.utc), None) is None

    def test_both_none(self):
        assert whois._days_between(None, None) is None


class TestRiskIndicatorsDirect:
    """Test ``_risk_indicators()`` pure function directly."""

    _NOW = datetime(2024, 6, 15, 12, 0, 0, tzinfo=timezone.utc)

    def test_newly_registered(self):
        risks = whois._risk_indicators(
            creation=self._NOW - timedelta(days=5),
            updated=None,
            expiry_status="healthy",
            privacy_protected=False,
            statuses=[],
            tld="com",
            now=self._NOW,
        )
        ids = {r["id"] for r in risks}
        assert "newly_registered" in ids

    def test_not_newly_registered_after_30_days(self):
        risks = whois._risk_indicators(
            creation=self._NOW - timedelta(days=31),
            updated=None,
            expiry_status="healthy",
            privacy_protected=False,
            statuses=[],
            tld="com",
            now=self._NOW,
        )
        ids = {r["id"] for r in risks}
        assert "newly_registered" not in ids

    def test_expired_risk(self):
        risks = whois._risk_indicators(
            creation=self._NOW - timedelta(days=1000),
            updated=None,
            expiry_status="expired",
            privacy_protected=False,
            statuses=[],
            tld="com",
            now=self._NOW,
        )
        ids = {r["id"] for r in risks}
        assert "expired" in ids
        assert any(r["severity"] == "high" for r in risks if r["id"] == "expired")

    def test_expiring_soon_risk(self):
        risks = whois._risk_indicators(
            creation=self._NOW - timedelta(days=1000),
            updated=None,
            expiry_status="expiring_soon",
            privacy_protected=False,
            statuses=[],
            tld="com",
            now=self._NOW,
        )
        ids = {r["id"] for r in risks}
        assert "expiring_soon" in ids
        assert "expired" not in ids

    def test_privacy_protected_risk(self):
        risks = whois._risk_indicators(
            creation=self._NOW - timedelta(days=1000),
            updated=None,
            expiry_status="healthy",
            privacy_protected=True,
            statuses=[],
            tld="com",
            now=self._NOW,
        )
        ids = {r["id"] for r in risks}
        assert "privacy_protected" in ids

    def test_recently_updated_risk(self):
        risks = whois._risk_indicators(
            creation=self._NOW - timedelta(days=1000),
            updated=self._NOW - timedelta(days=3),
            expiry_status="healthy",
            privacy_protected=False,
            statuses=[],
            tld="com",
            now=self._NOW,
        )
        ids = {r["id"] for r in risks}
        assert "recently_updated" in ids

    def test_not_recently_updated_after_14_days(self):
        risks = whois._risk_indicators(
            creation=self._NOW - timedelta(days=1000),
            updated=self._NOW - timedelta(days=15),
            expiry_status="healthy",
            privacy_protected=False,
            statuses=[],
            tld="com",
            now=self._NOW,
        )
        ids = {r["id"] for r in risks}
        assert "recently_updated" not in ids

    def test_suspicious_status_risk(self):
        risks = whois._risk_indicators(
            creation=self._NOW - timedelta(days=1000),
            updated=None,
            expiry_status="healthy",
            privacy_protected=False,
            statuses=["clientHold"],
            tld="com",
            now=self._NOW,
        )
        ids = {r["id"] for r in risks}
        assert "suspicious_status" in ids

    def test_unusual_tld_risk(self):
        risks = whois._risk_indicators(
            creation=self._NOW - timedelta(days=1000),
            updated=None,
            expiry_status="healthy",
            privacy_protected=False,
            statuses=[],
            tld="zip",
            now=self._NOW,
        )
        ids = {r["id"] for r in risks}
        assert "unusual_tld" in ids
        assert any("zip" in r["label"] for r in risks if r["id"] == "unusual_tld")

    def test_common_tld_no_risk(self):
        risks = whois._risk_indicators(
            creation=self._NOW - timedelta(days=1000),
            updated=None,
            expiry_status="healthy",
            privacy_protected=False,
            statuses=[],
            tld="com",
            now=self._NOW,
        )
        ids = {r["id"] for r in risks}
        assert "unusual_tld" not in ids

    def test_all_risks_together(self):
        risks = whois._risk_indicators(
            creation=self._NOW - timedelta(days=3),
            updated=self._NOW - timedelta(days=2),
            expiry_status="expiring_soon",
            privacy_protected=True,
            statuses=["clientHold"],
            tld="zip",
            now=self._NOW,
        )
        ids = {r["id"] for r in risks}
        assert ids == {
            "newly_registered", "expiring_soon", "privacy_protected",
            "recently_updated", "suspicious_status", "unusual_tld",
        }

    def test_no_risks(self):
        risks = whois._risk_indicators(
            creation=self._NOW - timedelta(days=1000),
            updated=self._NOW - timedelta(days=100),
            expiry_status="healthy",
            privacy_protected=False,
            statuses=["ok"],
            tld="com",
            now=self._NOW,
        )
        assert risks == []


# ======================================================================
# Computed fields through whois_lookup() — uses relative dates
# ======================================================================


class TestComputedFieldsIntegration:
    """Verify computed fields through the full ``whois_lookup()`` pipeline.

    Uses relative dates (fixture-relative to ``datetime.now()``) so tests
    are deterministic regardless of the calendar date they run on.
    No datetime mocking is needed.
    """

    @pytest.mark.asyncio
    async def test_healthy_domain_computed_fields(self, clear_cache, healthy_whois):
        result = await _run_lookup("healthy.com", healthy_whois, None)

        assert result.domain_age_days is not None
        assert result.domain_age_days >= 999
        assert result.days_until_expiry is not None
        assert result.days_until_expiry >= 364
        assert result.expiry_status == "healthy"

    @pytest.mark.asyncio
    async def test_expiring_soon_domain_computed_fields(self, clear_cache, expiring_soon_whois):
        result = await _run_lookup("expiring.com", expiring_soon_whois, None)

        assert result.days_until_expiry is not None
        assert 14 <= result.days_until_expiry <= 16
        assert result.expiry_status == "expiring_soon"

    @pytest.mark.asyncio
    async def test_expired_domain_computed_fields(self, clear_cache, expired_whois):
        result = await _run_lookup("expired.com", expired_whois, None)

        assert result.days_until_expiry is not None
        assert result.days_until_expiry < 0
        assert result.expiry_status == "expired"

    @pytest.mark.asyncio
    async def test_newly_registered_domain_age(self, clear_cache, newly_registered_whois):
        result = await _run_lookup("newdomain.com", newly_registered_whois, None)

        assert result.domain_age_days is not None
        assert 4 <= result.domain_age_days <= 6

    @pytest.mark.asyncio
    async def test_missing_creation_date_gives_none_age(
        self, clear_cache, partial_response, empty_rdap_response,
    ):
        result = await _run_lookup("partial.com", partial_response, empty_rdap_response)
        assert result.domain_age_days is None

    @pytest.mark.asyncio
    async def test_missing_expiration_gives_none_expiry_fields(
        self, clear_cache, partial_response, empty_rdap_response,
    ):
        result = await _run_lookup("partial.com", partial_response, empty_rdap_response)
        assert result.days_until_expiry is None
        assert result.expiry_status is None

    @pytest.mark.asyncio
    async def test_rdap_fallback_for_dates(self, clear_cache, mock_rdap_response):
        """When WHOIS has no dates but RDAP does, computed fields should be populated."""
        w = whois._normalize_target  # just need a reference; we'll use partial_response
        from tests.core.tools.whois.conftest import _make_whois_obj
        w_no_dates = _make_whois_obj(
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
        result = await _run_lookup("example.com", w_no_dates, mock_rdap_response)

        # RDAP has dates 2020-01-01 → 2025-01-01
        assert result.domain_age_days is not None
        assert result.domain_age_days > 0
        assert result.days_until_expiry is not None
        assert result.expiry_status is not None

    @pytest.mark.asyncio
    async def test_both_sources_fail_computed_fields_none(self, clear_cache):
        """When both WHOIS and RDAP fail, computed date fields are None."""
        def raise_exc(d):
            raise Exception("Connection refused")

        with patch("cybersec.core.tools.whois.python_whois.whois", side_effect=raise_exc), \
             patch("cybersec.core.tools.whois._fetch_rdap", return_value=None), \
             patch("cybersec.core.tools.whois._get_redis", return_value=None):
            result = await whois.whois_lookup("fail.com")

        assert result.domain_age_days is None
        assert result.days_until_expiry is None
        assert result.expiry_status is None

    @pytest.mark.asyncio
    async def test_creation_today_age_zero(self, clear_cache, make_whois_obj, relative_now):
        """Domain created right now should have age ~0."""
        w = make_whois_obj(
            domain_name="today.com",
            registrar="Test",
            creation_date=relative_now,
            expiration_date=relative_now + timedelta(days=365),
            updated_date=relative_now,
            name_servers=["ns1.test.com"],
            status=["ok"],
            emails=["a@b.com"],
            org="X",
            country="US",
            text="Domain Name: TODAY.COM",
        )
        result = await _run_lookup("today.com", w, None)
        assert result.domain_age_days is not None
        assert result.domain_age_days == 0

    @pytest.mark.asyncio
    async def test_expiry_today_is_expiring_soon(self, clear_cache, make_whois_obj, relative_now):
        """Domain expiring 'today' (0 days) should be expiring_soon."""
        w = make_whois_obj(
            domain_name="today.com",
            registrar="Test",
            creation_date=relative_now - timedelta(days=365),
            expiration_date=relative_now + timedelta(minutes=5),
            updated_date=relative_now - timedelta(days=30),
            name_servers=["ns1.test.com"],
            status=["ok"],
            emails=["a@b.com"],
            org="X",
            country="US",
            text="Domain Name: TODAY.COM",
        )
        result = await _run_lookup("today.com", w, None)
        assert result.expiry_status == "expiring_soon"

