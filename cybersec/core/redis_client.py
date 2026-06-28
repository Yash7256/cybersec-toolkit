import asyncio
import logging
import time
from typing import Optional

import redis.asyncio as aioredis
from cybersec.config.settings import settings

logger = logging.getLogger(__name__)

ACQUIRE_SLOT_SCRIPT = """
local current = tonumber(redis.call('GET', KEYS[1]) or '0')
local limit = tonumber(ARGV[1])
if current < limit then
    return redis.call('INCR', KEYS[1])
else
    return -1
end
"""


class RedisKeys:
    """Centralized Redis key namespacing. All new Redis keys in the
    app should be built through this class rather than hand-written
    f-strings, to guarantee no two features can accidentally collide
    on the same key.

    Any new feature that needs a Redis key MUST add a method here rather than
    hand-writing a key string elsewhere in the codebase. This is the single
    place to check for key collisions before adding a new prefix."""

    @staticmethod
    def cve(service: str, version: str | None) -> str:
        return f"cve:{service}:{version or ''}"

    @staticmethod
    def whois(domain: str) -> str:
        return f"whois:{domain}"

    @staticmethod
    def scan_events(scan_id: str) -> str:
        return f"scan:events:{scan_id}"

    @staticmethod
    def scan_global_active() -> str:
        return "scans:global:active"

    @staticmethod
    def scan_user_active(user_id: str) -> str:
        return f"scans:user:{user_id}:active"

    @staticmethod
    def threat_intel(ip: str) -> str:
        return f"threat_intel:{ip}"

    @staticmethod
    def ai_recommendations(fingerprint_hash: str) -> str:
        return f"ai_recs:{fingerprint_hash}"

    @staticmethod
    def os_fingerprint(ip: str) -> str:
        return f"os_fingerprint:{ip}"

_shared_client: Optional["aioredis.Redis"] = None


def get_shared_redis_client() -> Optional["aioredis.Redis"]:
    """Returns a process-wide shared Redis client with connection pooling.
    Returns None if client creation fails (caller should fall back to non-Redis behavior)."""
    global _shared_client
    if _shared_client is None:
        try:
            _shared_client = aioredis.from_url(
                settings.REDIS_URL,
                decode_responses=True,
                socket_connect_timeout=3.0,
                socket_timeout=5.0,
                max_connections=20,
            )
        except Exception:
            return None
    return _shared_client


async def close_shared_redis_client() -> None:
    global _shared_client
    if _shared_client is not None:
        try:
            await _shared_client.aclose()
        except Exception:
            pass
        _shared_client = None


class RedisCircuitBreaker:
    """
    Shared circuit breaker + connection factory for all Redis clients
    in the app. After `failure_threshold` consecutive failures, the
    breaker "opens" and all calls short-circuit to None (treated as
    Redis-unavailable) for `reset_timeout_seconds`, after which it
    allows one trial call through ("half-open") to test recovery.
    """
    def __init__(self, failure_threshold: int = 3, reset_timeout_seconds: float = 30.0):
        self.failure_threshold = failure_threshold
        self.reset_timeout_seconds = reset_timeout_seconds
        self._consecutive_failures = 0
        self._opened_at: Optional[float] = None
        self._lock = asyncio.Lock()

    async def is_open(self) -> bool:
        async with self._lock:
            if self._opened_at is None:
                return False
            if time.monotonic() - self._opened_at >= self.reset_timeout_seconds:
                # half-open: allow next call through as a trial
                self._opened_at = None
                self._consecutive_failures = 0
                logger.info("Redis circuit breaker half-open — allowing trial call")
                return False
            return True

    async def record_success(self) -> None:
        async with self._lock:
            self._consecutive_failures = 0
            self._opened_at = None

    async def record_failure(self) -> None:
        async with self._lock:
            self._consecutive_failures += 1
            if self._consecutive_failures >= self.failure_threshold and self._opened_at is None:
                self._opened_at = time.monotonic()
                logger.warning(
                    "Redis circuit breaker OPEN after %d consecutive failures — "
                    "short-circuiting for %.0fs",
                    self._consecutive_failures, self.reset_timeout_seconds,
                )


_breaker = RedisCircuitBreaker()


async def try_acquire_slot(r, key: str, limit: int) -> bool:
    """Atomically check-and-increment a Redis counter against a limit.
    Returns True if the slot was acquired (counter incremented and is
    within limit), False if the limit was already reached. This uses a
    Lua script via EVAL so the check-and-increment is a single atomic
    Redis operation — no race window exists between reading the current
    count and incrementing it, unlike a separate GET then INCR.
    Note: This still doesn't make release fully race-free against process
    crashes (leak risk remains for crash scenarios), but it closes the specific
    race where two concurrent acquires could both succeed past the limit.
    """
    result = await r.eval(ACQUIRE_SLOT_SCRIPT, 1, key, str(limit))
    return result != -1


def get_shared_breaker() -> RedisCircuitBreaker:
    return _breaker
