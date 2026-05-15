"""
Redis connection management for the scan job queue.
"""
import logging
from typing import Optional

from cybersec.config.settings import settings

logger = logging.getLogger(__name__)

_redis: Optional["Redis"] = None

# Redis stream / consumer group names
SCAN_STREAM = "scan_jobs"
SCAN_GROUP = "scan_workers"
RESULT_PREFIX = "scan_result:"


def _create_client():
    try:
        import redis.asyncio as aioredis
        return aioredis.from_url(
            settings.REDIS_URL,
            decode_responses=True,
            socket_connect_timeout=3.0,
            socket_timeout=5.0,
        )
    except Exception as e:
        logger.warning("Redis unavailable (%s) — scans will run in-process", e)
        return None


async def get_redis():
    global _redis
    if _redis is None:
        _redis = _create_client()
    return _redis


async def close_redis():
    global _redis
    if _redis is not None:
        try:
            await _redis.aclose()
        except Exception:
            pass
        _redis = None


async def ensure_stream_group():
    """Create the consumer group if it doesn't exist (idempotent)."""
    r = await get_redis()
    if r is None:
        return
    try:
        await r.xgroup_create(SCAN_STREAM, SCAN_GROUP, id="0", mkstream=True)
    except Exception as e:
        if "BUSYGROUP" not in str(e):
            logger.debug("Stream group setup: %s", e)


async def redis_available() -> bool:
    r = await get_redis()
    if r is None:
        return False
    try:
        await r.ping()
        return True
    except Exception:
        return False
