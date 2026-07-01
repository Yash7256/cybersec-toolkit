"""
Tier enforcement utilities for the CyberSec API.

Free users are limited to FREE_TIER_DAILY_LIMIT executions **per tool** per
calendar day.  Each tool has its own independent counter so running DNS 5 times
does not affect the user's ability to run a port scan.

Paid users and superusers are never gated.

All tool endpoints now require authentication (get_current_user), so `user`
will always be a real User instance when this function is called.  The None
guard is kept as a safety net in case the function is called from other contexts.

Usage in a route:
    from cybersec.apps.api.tier import check_and_increment_usage

    @router.post("/dns")
    async def dns(..., current_user: User = Depends(get_current_user), db = Depends(get_db)):
        await check_and_increment_usage(current_user, db, tool_name="dns")
        ...
"""
import datetime
import logging

from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.attributes import flag_modified

from cybersec.database.models import User

logger = logging.getLogger(__name__)

FREE_TIER_DAILY_LIMIT: int = 5


async def check_and_increment_usage(
    user: User | None,
    db: AsyncSession,
    tool_name: str = "unknown",
) -> None:
    """Enforce the free-tier daily tool usage limit on a per-tool basis.

    Each tool has its own independent counter that resets at midnight UTC.
    Using DNS 5 times does NOT prevent the user from using port scan.

    Args:
        user:      The current authenticated user, or None (safety net — always passes).
        db:        An open async SQLAlchemy session.
        tool_name: Identifier for the tool being called (e.g. "dns", "whois").

    Raises:
        HTTPException(429): When a free-tier user has exhausted their daily quota
                            for this specific tool.
    """
    # Safety net — anonymous pass-through (routes now require auth, but kept for safety)
    if user is None:
        return

    # Superusers and paid users — always allowed
    if user.is_superuser or user.tier == "paid":
        return

    today = datetime.date.today().isoformat()  # "YYYY-MM-DD"

    # Load current per-tool usage dict (JSONB column, may be None on legacy rows)
    tool_usage: dict = user.tool_usage if user.tool_usage is not None else {}

    # Get or initialise this tool's entry
    entry = tool_usage.get(tool_name)
    if entry is None or entry.get("date") != today:
        # First use today for this tool — reset counter
        logger.debug(
            "tier: resetting counter for user %s tool=%s (was %s)",
            user.id,
            tool_name,
            entry,
        )
        entry = {"count": 0, "date": today}

    current_count: int = entry.get("count", 0)

    # Enforce the limit before incrementing
    if current_count >= FREE_TIER_DAILY_LIMIT:
        logger.info(
            "tier: free user %s hit daily limit for tool=%s (%d/%d)",
            user.id,
            tool_name,
            current_count,
            FREE_TIER_DAILY_LIMIT,
        )
        raise HTTPException(
            status_code=429,
            detail={
                "code": "daily_limit_reached",
                "message": (
                    f"Free tier allows {FREE_TIER_DAILY_LIMIT} uses of '{tool_name}' per day. "
                    "Upgrade to Paid for unlimited access."
                ),
                "tool": tool_name,
                "limit": FREE_TIER_DAILY_LIMIT,
                "used": current_count,
                "remaining": 0,
                "tier": user.tier,
            },
        )

    # Increment counter
    entry["count"] = current_count + 1

    # Build a new dict and reassign so SQLAlchemy detects the JSONB mutation
    updated_usage = {**tool_usage, tool_name: entry}
    user.tool_usage = updated_usage

    # Explicitly mark the JSONB column dirty — required when mutating nested dicts
    # because SQLAlchemy may not detect in-place changes to mutable JSON columns.
    flag_modified(user, "tool_usage")

    logger.debug(
        "tier: user %s tool=%s usage %d/%d",
        user.id,
        tool_name,
        entry["count"],
        FREE_TIER_DAILY_LIMIT,
    )

    await db.commit()


def get_usage_status(user: User, tool_name: str) -> dict:
    """Return current usage status for a tool without modifying anything.

    Returns a dict with keys: count, remaining, limit, reset_at (next midnight ISO).
    Useful for returning usage info in response headers or the /api/user/me endpoint.
    """
    today = datetime.date.today().isoformat()

    if user.is_superuser or user.tier == "paid":
        return {
            "count": 0,
            "remaining": None,  # unlimited
            "limit": None,
            "reset_at": None,
        }

    tool_usage: dict = user.tool_usage if user.tool_usage is not None else {}
    entry = tool_usage.get(tool_name)

    if entry is None or entry.get("date") != today:
        count = 0
    else:
        count = entry.get("count", 0)

    tomorrow = (datetime.date.today() + datetime.timedelta(days=1)).isoformat()

    return {
        "count": count,
        "remaining": max(0, FREE_TIER_DAILY_LIMIT - count),
        "limit": FREE_TIER_DAILY_LIMIT,
        "reset_at": f"{tomorrow}T00:00:00",
    }
