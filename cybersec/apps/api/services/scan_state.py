import asyncio
import logging
import time
from cybersec.core.metrics_registry import (
    _registry,
    scan_active,
    scan_queue_depth,
    scan_total,
)
from cybersec.core.events import publish_event
from cybersec.config import settings
from cybersec.core.redis_client import RedisKeys


class _MetricsProxy:
    """Lazy metric references to avoid import-order issues."""
    sse_drops = _registry.counter("sse_drop_total", "SSE events dropped due to full queue")


_metrics = _MetricsProxy()

logger = logging.getLogger(__name__)

# In-memory scan stores used when the database is unavailable.
scan_meta: dict[str, dict] = {}

# Bounded: keeps at most MAX_RESULTS_PER_SCAN entries per scan
scan_results: dict[str, list[dict]] = {}
MAX_RESULTS_PER_SCAN = 10_000

scan_progress: dict[str, dict] = {}

# Bounded: each queue holds at most QUEUE_MAXSIZE events
scan_events: dict[str, asyncio.Queue] = {}
QUEUE_MAXSIZE = 1000

# Task registry for cancellation
scan_tasks: dict[str, asyncio.Task] = {}

# ── Scan scheduler / isolation limits ─────────────────────────────────
MAX_CONCURRENT_SCANS_GLOBAL = 20
MAX_CONCURRENT_SCANS_PER_USER = 3


# In-memory fallbacks for when Redis is unavailable
_scan_slot_fallback = asyncio.Semaphore(MAX_CONCURRENT_SCANS_GLOBAL)
_user_scan_count_fallback: dict[str, int] = {}
_user_lock_fallback = asyncio.Lock()


async def _fallback_acquire_global() -> bool:
    """Fallback in-memory acquire for global slot when Redis is down."""
    await asyncio.wait_for(_scan_slot_fallback.acquire(), timeout=30.0)
    return True


async def _fallback_release_global() -> None:
    """Fallback in-memory release for global slot when Redis is down."""
    _scan_slot_fallback.release()


async def _fallback_acquire_user(user_id: str) -> bool:
    """Fallback in-memory acquire for per-user quota when Redis is down."""
    async with _user_lock_fallback:
        current = _user_scan_count_fallback.get(user_id, 0)
        if current >= MAX_CONCURRENT_SCANS_PER_USER:
            logger.warning(
                "User %s at scan quota (%d/%d)",
                user_id, current, MAX_CONCURRENT_SCANS_PER_USER,
            )
            return False
        _user_scan_count_fallback[user_id] = current + 1
    return True


async def _fallback_release_user(user_id: str) -> None:
    """Fallback in-memory release for per-user quota when Redis is down."""
    async with _user_lock_fallback:
        current = _user_scan_count_fallback.get(user_id, 0)
        if current > 1:
            _user_scan_count_fallback[user_id] = current - 1
        else:
            _user_scan_count_fallback.pop(user_id, None)


async def acquire_global_scan_slot(timeout: float = 30.0) -> bool:
    """Acquire a global scan slot with Redis, falling back to in-memory if Redis is down."""
    from cybersec.core.redis_client import get_shared_redis_client, try_acquire_slot
    r = get_shared_redis_client()
    if r is None:
        # Redis unavailable — fall back to existing in-memory behavior
        return await _fallback_acquire_global()

    deadline = time.monotonic() + timeout
    key = RedisKeys.scan_global_active()
    while time.monotonic() < deadline:
        try:
            if await try_acquire_slot(r, key, MAX_CONCURRENT_SCANS_GLOBAL):
                return True
        except Exception as e:
            logger.warning("Redis slot acquisition failed, falling back: %s", e)
            return await _fallback_acquire_global()
        await asyncio.sleep(0.1)
    return False


async def release_global_scan_slot() -> None:
    """Release a global scan slot with Redis, falling back to in-memory if Redis is down."""
    from cybersec.core.redis_client import get_shared_redis_client
    r = get_shared_redis_client()
    if r is not None:
        await r.decr(RedisKeys.scan_global_active())
    else:
        await _fallback_release_global()


async def acquire_user_scan_slot(user_id: str) -> bool:
    """Acquire a per-user scan slot with Redis, falling back to in-memory if Redis is down."""
    from cybersec.core.redis_client import get_shared_redis_client, try_acquire_slot
    r = get_shared_redis_client()
    if r is None:
        return await _fallback_acquire_user(user_id)

    key = RedisKeys.scan_user_active(user_id)
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        try:
            if await try_acquire_slot(r, key, MAX_CONCURRENT_SCANS_PER_USER):
                return True
        except Exception as e:
            logger.warning("Redis user slot acquisition failed, falling back: %s", e)
            return await _fallback_acquire_user(user_id)
        await asyncio.sleep(0.1)
    return False


async def release_user_scan_slot(user_id: str) -> None:
    """Release a per-user scan slot with Redis, falling back to in-memory if Redis is down."""
    from cybersec.core.redis_client import get_shared_redis_client
    r = get_shared_redis_client()
    if r is not None:
        key = RedisKeys.scan_user_active(user_id)
        await r.decr(key)
    else:
        await _fallback_release_user(user_id)


async def acquire_scan_slot(user_id: str | None) -> bool:
    """Try to acquire a scan slot. Returns True if granted.

    Acquires the global semaphore FIRST, then checks the per-user quota.
    This prevents quota state from leaking when the semaphore times out.
    """
    scan_total().inc(1)

    global_acquired = await acquire_global_scan_slot(timeout=30.0)
    if not global_acquired:
        return False

    scan_active().inc(1)
    scan_queue_depth().set(MAX_CONCURRENT_SCANS_GLOBAL - 1)

    if user_id is not None:
        user_acquired = await acquire_user_scan_slot(user_id)
        if not user_acquired:
            await release_global_scan_slot()
            scan_active().dec(1)
            return False

    return True


async def release_scan_slot(user_id: str | None) -> None:
    """Release a scan slot, allowing the next queued scan to start."""
    scan_active().dec(1)
    scan_queue_depth().set(MAX_CONCURRENT_SCANS_GLOBAL - 1)
    try:
        await release_global_scan_slot()
    except Exception as e:
        logger.error(
            "Failed to release global scan slot — this scan slot may leak: %s",
            e
        )
    if user_id:
        try:
            await release_user_scan_slot(user_id)
        except Exception as e:
            logger.error(
                "Failed to release user scan slot for %s — this slot may leak: %s",
                user_id,
                e
            )


async def safe_queue_put(scan_id: str, event: str, critical: bool = False) -> None:
    """Put an event onto the scan's SSE event bus (Redis Pub/Sub or in-memory).

    Args:
        scan_id: Scan to publish for.
        event: JSON string or "[DONE]" sentinel.
        critical: If True, uses blocking put() so terminal events
                  ([DONE], scan_complete) are NEVER dropped.
                  If False, uses put_nowait() — drops on overflow.
    """
    queue = scan_events.get(scan_id)
    if queue is not None:
        try:
            if critical:
                await queue.put(event)
            else:
                queue.put_nowait(event)
        except asyncio.QueueFull:
            _metrics.sse_drops.inc()

    await publish_event(scan_id, event)


def append_result(scan_id: str, evt: dict) -> None:
    """Append a result, trimming to MAX_RESULTS_PER_SCAN."""
    results = scan_results.get(scan_id)
    if results is None:
        return

    results.append(evt)
    if len(results) > MAX_RESULTS_PER_SCAN:
        dropped = results[:len(results) - MAX_RESULTS_PER_SCAN]
        results[:] = results[len(dropped):]
        logger.warning(
            "Trimmed %d old results for scan %s (limit %d)",
            len(dropped), scan_id, MAX_RESULTS_PER_SCAN,
        )


def register_task(scan_id: str, task: asyncio.Task) -> None:
    """Register a running scan task for cancellation."""
    scan_tasks[scan_id] = task


def unregister_task(scan_id: str) -> None:
    """Remove a scan task from the registry."""
    scan_tasks.pop(scan_id, None)


async def cancel_scan(scan_id: str) -> bool:
    """Cancel a running scan by scan_id. Returns True if cancelled."""
    task = scan_tasks.pop(scan_id, None)
    if task is None or task.done():
        return False

    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    return True


def cleanup_scan(scan_id: str) -> None:
    """Remove all in-memory state for a scan."""
    scan_events.pop(scan_id, None)
    scan_meta.pop(scan_id, None)
    scan_results.pop(scan_id, None)
    scan_progress.pop(scan_id, None)
    unregister_task(scan_id)

