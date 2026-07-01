"""
Unit tests for tier enforcement.

Tests check_and_increment_usage for free users (below/at limit),
new-day reset behaviour, paid/superuser bypass, anonymous pass-through,
and per-tool independence (using dns does not affect whois counter).
"""
import datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import HTTPException

from cybersec.apps.api.tier import (
    FREE_TIER_DAILY_LIMIT,
    check_and_increment_usage,
    get_usage_status,
)

TODAY = datetime.date.today().isoformat()
YESTERDAY = (datetime.date.today() - datetime.timedelta(days=1)).isoformat()


def _make_user(tier="free", tool_usage=None, is_superuser=False):
    """Helper: build a minimal user-like object for tier tests.

    Uses SimpleNamespace instead of the real SQLAlchemy User to avoid
    needing a mapped session — tier.py only accesses .id, .tier,
    .tool_usage, and .is_superuser.
    """
    return SimpleNamespace(
        id="test-user-id",
        tier=tier,
        tool_usage=tool_usage if tool_usage is not None else {},
        is_superuser=is_superuser,
    )


# ---------------------------------------------------------------------------
# Anonymous / bypass tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_anonymous_user_always_passes():
    """Anonymous (None) user should never be rate-limited."""
    db = AsyncMock()
    await check_and_increment_usage(None, db, tool_name="dns")
    db.commit.assert_not_called()


@pytest.mark.asyncio
async def test_superuser_always_passes():
    """Superusers bypass all tier checks regardless of usage."""
    user = _make_user(
        tier="free",
        tool_usage={"dns": {"count": 99, "date": TODAY}},
        is_superuser=True,
    )
    db = AsyncMock()
    await check_and_increment_usage(user, db, tool_name="dns")
    db.commit.assert_not_called()


@pytest.mark.asyncio
async def test_paid_user_always_passes():
    """Paid-tier users bypass all tier checks."""
    user = _make_user(
        tier="paid",
        tool_usage={"dns": {"count": 99, "date": TODAY}},
    )
    db = AsyncMock()
    await check_and_increment_usage(user, db, tool_name="dns")
    db.commit.assert_not_called()


# ---------------------------------------------------------------------------
# Per-tool increment / limit tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_free_user_first_use_of_tool():
    """First use of a tool for a free user creates the entry and sets count=1."""
    user = _make_user(tier="free", tool_usage={})
    db = AsyncMock()
    with patch("cybersec.apps.api.tier.flag_modified"):
        await check_and_increment_usage(user, db, tool_name="dns")

    assert user.tool_usage["dns"]["count"] == 1
    assert user.tool_usage["dns"]["date"] == TODAY
    db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_free_user_below_limit_increments():
    """Free user under the daily limit should have the tool counter incremented."""
    user = _make_user(
        tier="free",
        tool_usage={"dns": {"count": 2, "date": TODAY}},
    )
    db = AsyncMock()
    with patch("cybersec.apps.api.tier.flag_modified"):
        await check_and_increment_usage(user, db, tool_name="dns")

    assert user.tool_usage["dns"]["count"] == 3
    db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_free_user_at_limit_raises_429():
    """Free user who has hit the daily limit for a tool gets HTTP 429."""
    user = _make_user(
        tier="free",
        tool_usage={"dns": {"count": FREE_TIER_DAILY_LIMIT, "date": TODAY}},
    )
    db = AsyncMock()

    with pytest.raises(HTTPException) as exc:
        await check_and_increment_usage(user, db, tool_name="dns")

    assert exc.value.status_code == 429
    detail = exc.value.detail
    assert detail["code"] == "daily_limit_reached"
    assert detail["tool"] == "dns"
    assert detail["limit"] == FREE_TIER_DAILY_LIMIT
    assert detail["used"] == FREE_TIER_DAILY_LIMIT
    assert detail["remaining"] == 0
    assert detail["tier"] == "free"
    # Counter should NOT be incremented past the limit
    assert user.tool_usage["dns"]["count"] == FREE_TIER_DAILY_LIMIT
    db.commit.assert_not_called()


@pytest.mark.asyncio
async def test_limit_at_exactly_free_tier_daily_limit():
    """Free user with exactly FREE_TIER_DAILY_LIMIT for a tool should be blocked."""
    user = _make_user(
        tier="free",
        tool_usage={"whois": {"count": FREE_TIER_DAILY_LIMIT, "date": TODAY}},
    )
    db = AsyncMock()
    with pytest.raises(HTTPException) as exc:
        await check_and_increment_usage(user, db, tool_name="whois")
    assert exc.value.status_code == 429


@pytest.mark.asyncio
async def test_free_user_exactly_one_below_limit_increments():
    """Free user at limit-1 for a tool should be allowed and reach the limit."""
    user = _make_user(
        tier="free",
        tool_usage={"ssl": {"count": FREE_TIER_DAILY_LIMIT - 1, "date": TODAY}},
    )
    db = AsyncMock()
    with patch("cybersec.apps.api.tier.flag_modified"):
        await check_and_increment_usage(user, db, tool_name="ssl")

    assert user.tool_usage["ssl"]["count"] == FREE_TIER_DAILY_LIMIT
    db.commit.assert_awaited_once()


# ---------------------------------------------------------------------------
# Per-tool independence test
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_tools_are_independent():
    """Exhausting dns limit should not affect whois counter."""
    user = _make_user(
        tier="free",
        tool_usage={
            "dns": {"count": FREE_TIER_DAILY_LIMIT, "date": TODAY},
            "whois": {"count": 1, "date": TODAY},
        },
    )
    db = AsyncMock()

    # dns is at limit — should raise
    with pytest.raises(HTTPException):
        await check_and_increment_usage(user, db, tool_name="dns")

    # whois is not at limit — should succeed
    db.reset_mock()
    with patch("cybersec.apps.api.tier.flag_modified"):
        await check_and_increment_usage(user, db, tool_name="whois")
    assert user.tool_usage["whois"]["count"] == 2
    db.commit.assert_awaited_once()


# ---------------------------------------------------------------------------
# Day-reset tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_reset_counter_new_day():
    """Stale entry from yesterday gets reset to count=1 on new day use."""
    user = _make_user(
        tier="free",
        tool_usage={"dns": {"count": FREE_TIER_DAILY_LIMIT, "date": YESTERDAY}},
    )
    db = AsyncMock()
    with patch("cybersec.apps.api.tier.flag_modified"):
        await check_and_increment_usage(user, db, tool_name="dns")

    assert user.tool_usage["dns"]["count"] == 1
    assert user.tool_usage["dns"]["date"] == TODAY
    db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_reset_counter_no_entry():
    """Tool with no prior entry behaves like a fresh first use."""
    user = _make_user(tier="free", tool_usage={})
    db = AsyncMock()
    with patch("cybersec.apps.api.tier.flag_modified"):
        await check_and_increment_usage(user, db, tool_name="geoip")

    assert user.tool_usage["geoip"]["count"] == 1
    assert user.tool_usage["geoip"]["date"] == TODAY
    db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_stale_entry_does_not_block():
    """User who hit the limit yesterday should be unblocked today."""
    user = _make_user(
        tier="free",
        tool_usage={"ping": {"count": FREE_TIER_DAILY_LIMIT, "date": YESTERDAY}},
    )
    db = AsyncMock()
    with patch("cybersec.apps.api.tier.flag_modified"):
        await check_and_increment_usage(user, db, tool_name="ping")
    assert user.tool_usage["ping"]["count"] == 1
    db.commit.assert_awaited_once()


# ---------------------------------------------------------------------------
# get_usage_status helper tests
# ---------------------------------------------------------------------------

def test_get_usage_status_free_no_entry():
    """Free user with no prior usage should have full remaining count."""
    user = _make_user(tier="free", tool_usage={})
    status = get_usage_status(user, "dns")
    assert status["count"] == 0
    assert status["remaining"] == FREE_TIER_DAILY_LIMIT
    assert status["limit"] == FREE_TIER_DAILY_LIMIT
    assert status["reset_at"] is not None


def test_get_usage_status_free_partial():
    """Free user mid-way through daily limit."""
    user = _make_user(
        tier="free",
        tool_usage={"dns": {"count": 3, "date": TODAY}},
    )
    status = get_usage_status(user, "dns")
    assert status["count"] == 3
    assert status["remaining"] == FREE_TIER_DAILY_LIMIT - 3


def test_get_usage_status_free_stale():
    """Stale entry from yesterday shows as count=0."""
    user = _make_user(
        tier="free",
        tool_usage={"dns": {"count": FREE_TIER_DAILY_LIMIT, "date": YESTERDAY}},
    )
    status = get_usage_status(user, "dns")
    assert status["count"] == 0
    assert status["remaining"] == FREE_TIER_DAILY_LIMIT


def test_get_usage_status_paid():
    """Paid user always gets unlimited status."""
    user = _make_user(tier="paid")
    status = get_usage_status(user, "dns")
    assert status["remaining"] is None
    assert status["limit"] is None


def test_get_usage_status_superuser():
    """Superuser always gets unlimited status."""
    user = _make_user(tier="free", is_superuser=True)
    status = get_usage_status(user, "dns")
    assert status["remaining"] is None
