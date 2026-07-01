"""
User profile and tier status routes.

GET /api/user/me
  Returns the current user's tier, per-tool usage counts, daily limit, and
  remaining uses per tool.  Requires authentication — returns 401 for anonymous.
"""
import datetime

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from cybersec.apps.api.deps import get_db, get_current_user
from cybersec.apps.api.tier import FREE_TIER_DAILY_LIMIT
from cybersec.database.models import User

router = APIRouter()

# All tools that have tier enforcement — used to show 0 remaining for tools
# the user hasn't touched yet today so the frontend can show full status.
TRACKED_TOOLS = [
    "dns", "whois", "ping", "traceroute", "ssl",
    "http_headers", "subdomain", "geoip", "os_fingerprint",
    "port_scan", "webapp", "ai_chat", "ai_analyze",
]


@router.get("/me", tags=["user"])
async def get_me(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Return the current user's tier and per-tool daily usage info.

    Requires authentication. Returns 401 for unauthenticated requests.

    - **Free users** → tier=free, tool_usage map with per-tool counts + remaining.
    - **Paid users / superusers** → tier=paid, unlimited=True.

    Response shape:
    {
        "authenticated": true,
        "tier": "free" | "paid",
        "daily_limit": int | null,      # null for paid/unlimited
        "tool_usage": {
            "dns":     { "count": 2, "remaining": 3 },
            "whois":   { "count": 0, "remaining": 5 },
            ...
        },
        "unlimited": bool,
    }
    """
    is_unlimited = current_user.is_superuser or current_user.tier == "paid"

    if is_unlimited:
        return {
            "authenticated": True,
            "tier": "paid",
            "daily_limit": None,
            "tool_usage": {tool: {"count": 0, "remaining": None} for tool in TRACKED_TOOLS},
            "unlimited": True,
        }

    # Build per-tool usage from the JSONB column
    today = datetime.date.today().isoformat()
    raw: dict = current_user.tool_usage if current_user.tool_usage else {}

    tool_usage: dict[str, dict] = {}
    for tool in TRACKED_TOOLS:
        entry = raw.get(tool)
        if entry is not None and entry.get("date") == today:
            count = entry.get("count", 0)
        else:
            count = 0
        tool_usage[tool] = {
            "count": count,
            "remaining": max(0, FREE_TIER_DAILY_LIMIT - count),
        }

    return {
        "authenticated": True,
        "tier": current_user.tier,
        "daily_limit": FREE_TIER_DAILY_LIMIT,
        "tool_usage": tool_usage,
        "unlimited": False,
    }
