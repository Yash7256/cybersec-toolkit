import asyncio
import logging
from cybersec.core.metrics_registry import (
    registry as _registry,
    scan_active,
    scan_queue_depth,
    scan_total,
)
from cybersec.core.events import publish_event


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

# Semaphore for global scan slot
_scan_slot = asyncio.Semaphore(MAX_CONCURRENT_SCANS_GLOBAL)

# Active scan count per user (user_id -> count)
_user_scan_count: dict[str, int] = {}
_user_lock = asyncio.Lock()


async def acquire_scan_slot(user_id: str | None) -> bool:
    """Try to acquire a scan slot. Returns True if granted.

    Acquires the global semaphore FIRST, then checks the per-user quota.
    This prevents quota state from leaking when the semaphore times out.
    """
    scan_queue_depth().set(_scan_slot._value)
    scan_total().inc(1)

    await asyncio.wait_for(_scan_slot.acquire(), timeout=30.0)
    scan_active().inc(1)
    scan_queue_depth().set(_scan_slot._value)

    if user_id is not None:
        async with _user_lock:
            current = _user_scan_count.get(user_id, 0)
            if current >= MAX_CONCURRENT_SCANS_PER_USER:
                logger.warning(
                    "User %s at scan quota (%d/%d)",
                    user_id, current, MAX_CONCURRENT_SCANS_PER_USER,
                )
                _scan_slot.release()
                scan_active().dec(1)
                return False
            _user_scan_count[user_id] = current + 1

    return True


def release_scan_slot(user_id: str | None) -> None:
    """Release a scan slot, allowing the next queued scan to start."""
    scan_active().dec(1)
    _scan_slot.release()
    scan_queue_depth().set(_scan_slot._value)
    if user_id:
        current = _user_scan_count.get(user_id, 0)
        if current > 1:
            _user_scan_count[user_id] = current - 1
        else:
            _user_scan_count.pop(user_id, None)


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
