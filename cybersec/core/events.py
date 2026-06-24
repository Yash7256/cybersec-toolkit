"""
Distributed event bus for scan result streaming.

Uses Redis Streams for persistence, replay, and horizontal scaling:

  Worker/API  ──XADD──►  Redis Stream  ◄──XREAD──  SSE endpoint
                          (persistent)

Any API node can serve SSE for any scan. Clients can reconnect and
resume from the last received event via ?last_id= query parameter.

Falls back to in-memory asyncio.Queue when Redis is unavailable.
"""
import asyncio
import logging
from typing import Optional

from cybersec.config.settings import settings
from cybersec.core.redis_client import get_shared_breaker, get_shared_redis_client, close_shared_redis_client, RedisKeys

logger = logging.getLogger(__name__)

STREAM_MAXLEN = 10_000      # max events per scan stream
POLL_TIMEOUT = 55_000       # ms — matches SSE keepalive (55s)

# In-memory fallback
_local_queues: dict[str, asyncio.Queue] = {}


async def _get_redis():
    return get_shared_redis_client()


def _stream_key(scan_id: str) -> str:
    return RedisKeys.scan_events(scan_id)


# ── Producer ────────────────────────────────────────────────────────────────

async def publish_event(scan_id: str, event: str) -> None:
    """Append an event to the scan's Redis Stream.

    Falls back to in-memory queue if Redis is unavailable.
    """
    breaker = get_shared_breaker()
    if await breaker.is_open():
        # Skip straight to fallback — don't even attempt Redis
        q = _local_queues.get(scan_id)
        if q is not None:
            try:
                q.put_nowait(event)
                from cybersec.core.metrics_registry import sse_backlog
                sse_backlog().set(q.qsize())
            except asyncio.QueueFull:
                logger.warning("Local event queue full for scan %s", scan_id)
        return

    r = await _get_redis()
    if r is not None:
        try:
            key = _stream_key(scan_id)
            from cybersec.core.metrics_registry import redis_publish_duration
            _t0 = __import__("time").monotonic()
            await r.xadd(key, {"event": event}, maxlen=STREAM_MAXLEN, approximate=True)
            redis_publish_duration().observe(__import__("time").monotonic() - _t0)
            await breaker.record_success()
            return
        except Exception as e:
            await breaker.record_failure()
            logger.warning("Redis XADD failed for %s: %s", scan_id, e)

    q = _local_queues.get(scan_id)
    if q is not None:
        try:
            q.put_nowait(event)
            from cybersec.core.metrics_registry import sse_backlog
            sse_backlog().set(q.qsize())
        except asyncio.QueueFull:
            logger.warning("Local event queue full for scan %s — dropping event", scan_id)


# ── Consumer ─────────────────────────────────────────────────────────────────

async def subscribe_events(scan_id: str, last_id: str = "$",
                           maxsize: int = 1000) -> asyncio.Queue:
    """Subscribe to events for a scan via Redis Streams.

    Args:
        scan_id: Scan to stream events for.
        last_id: Stream ID to resume from ("$" = newest, "0" = all).
        maxsize: Local buffer size.

    Returns:
        asyncio.Queue — consumer reads events from this queue.
        Terminal event ("[DONE]") signals end.
    """
    breaker = get_shared_breaker()
    if await breaker.is_open():
        # Skip straight to fallback
        q = asyncio.Queue(maxsize=maxsize)
        _local_queues[scan_id] = q
        return q

    r = await _get_redis()
    if r is not None:
        try:
            q: asyncio.Queue = asyncio.Queue(maxsize=maxsize)
            key = _stream_key(scan_id)
            current_id = last_id

            async def _poll_loop():
                nonlocal current_id
                try:
                    while True:
                        if await breaker.is_open():
                            # Breaker opened mid-poll — exit loop to let consumer retry
                            return
                        try:
                            results = await r.xread(
                                streams={key: current_id},
                                count=1,
                                block=POLL_TIMEOUT,
                            )
                            await breaker.record_success()
                        except Exception as e:
                            await breaker.record_failure()
                            logger.warning("Redis xread failed for %s: %s", scan_id, e)
                            return  # exit loop to fall back

                        if not results:
                            continue  # timeout, retry

                        for _, messages in results:
                            for msg_id, msg_data in messages:
                                event = msg_data.get("event", "")
                                if event == "[DONE]":
                                    await q.put("[DONE]")
                                    return
                                try:
                                    q.put_nowait(event)
                                except asyncio.QueueFull:
                                    logger.warning(
                                        "SSE queue full for %s — dropping event", scan_id)
                                current_id = msg_id
                except asyncio.CancelledError:
                    pass

            task = asyncio.create_task(_poll_loop())
            q._cleanup_task = task
            return q

        except Exception as e:
            await breaker.record_failure()
            logger.warning("Redis stream subscribe failed for %s: %s", scan_id, e)

    # Fallback: local queue
    q = asyncio.Queue(maxsize=maxsize)
    _local_queues[scan_id] = q
    return q


async def unsubscribe_events(scan_id: str) -> None:
    """Clean up a subscription."""
    _local_queues.pop(scan_id, None)


async def close_redis():
    """Shut down Redis connection."""
    await close_shared_redis_client()
