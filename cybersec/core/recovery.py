"""
Scan state recovery — persists state to DB and recovers orphaned scans on restart.

Uses PostgreSQL as source of truth for scan lifecycle.

Workers send periodic heartbeats. A background reaper detects stale workers
and reclaims their scans.
"""
import asyncio
import logging
import os
import socket
from datetime import datetime, timezone, timedelta

from sqlalchemy import select

from cybersec.database.session import async_session_maker
from cybersec.database.models import Scan, WorkerHeartbeat

logger = logging.getLogger(__name__)

STALL_TIMEOUT = timedelta(seconds=120)
REAPER_INTERVAL = 60  # seconds between reaper cycles


# ── Worker heartbeat ─────────────────────────────────────────────────────────

async def register_worker(worker_id: str) -> None:
    """Register this worker in the heartbeat table."""
    try:
        async with async_session_maker() as db:
            existing = await db.get(WorkerHeartbeat, worker_id)
            if existing is None:
                db.add(WorkerHeartbeat(
                    worker_id=worker_id,
                    hostname=socket.gethostname(),
                    pid=os.getpid(),
                    last_heartbeat=datetime.now(timezone.utc),
                ))
                await db.commit()
    except Exception as e:
        logger.debug("Worker registration failed: %s", e)


async def worker_heartbeat(worker_id: str, active_scans: int = 0) -> None:
    """Update worker heartbeat timestamp and active scan count."""
    try:
        async with async_session_maker() as db:
            row = await db.get(WorkerHeartbeat, worker_id)
            if row is not None:
                row.last_heartbeat = datetime.now(timezone.utc)
                row.active_scans = active_scans
                await db.commit()
    except Exception as e:
        logger.debug("Worker heartbeat failed: %s", e)


async def unregister_worker(worker_id: str) -> None:
    """Remove worker from heartbeat table on graceful shutdown."""
    try:
        async with async_session_maker() as db:
            row = await db.get(WorkerHeartbeat, worker_id)
            if row is not None:
                await db.delete(row)
                await db.commit()
    except Exception as e:
        logger.debug("Worker unregister failed: %s", e)


# ── Scan state persistence ───────────────────────────────────────────────────

async def persist_heartbeat(scan_id: str, worker_id: str | None = None,
                            progress_pct: int = 0) -> None:
    """Update scan heartbeat and progress in DB."""
    try:
        async with async_session_maker() as db:
            scan = await db.get(Scan, scan_id)
            if scan is not None:
                scan.heartbeat_at = datetime.now(timezone.utc)
                if worker_id is not None:
                    scan.worker_id = worker_id
                if progress_pct > (scan.progress_pct or 0):
                    scan.progress_pct = progress_pct
                await db.commit()
    except Exception as e:
        logger.debug("Heartbeat persist failed for %s: %s", scan_id, e)


async def persist_status(scan_id: str, status: str,
                         error_message: str | None = None) -> None:
    """Persist scan status transition to DB."""
    try:
        async with async_session_maker() as db:
            scan = await db.get(Scan, scan_id)
            if scan is not None:
                scan.status = status
                if error_message:
                    scan.error_message = error_message
                if status in ("completed", "failed", "cancelled", "timed_out"):
                    scan.completed_at = datetime.now(timezone.utc)
                await db.commit()
    except Exception as e:
        logger.warning("Status persist failed for %s: %s", scan_id, e)


# ── Reaper: detect and recover orphaned scans ────────────────────────────────

async def reap_stale_workers() -> list[str]:
    """Find workers with stale heartbeats, reclaim their scans.

    Runs periodically as a background task.
    Marks both the worker and its scans as dead.
    """
    cutoff = datetime.now(timezone.utc) - STALL_TIMEOUT
    reclaimed: list[str] = []

    try:
        async with async_session_maker() as db:
            # 1. Find dead workers
            dead_workers = await db.execute(
                select(WorkerHeartbeat).where(WorkerHeartbeat.last_heartbeat < cutoff)
            )
            dead_ids = [w.worker_id for w in dead_workers.scalars().all()]

            if not dead_ids:
                return []

            # 2. Find scans owned by dead workers
            orphaned = await db.execute(
                select(Scan).where(
                    Scan.status == "running",
                    Scan.worker_id.in_(dead_ids),
                )
            )
            for scan in orphaned.scalars().all():
                scan.status = "timed_out"
                scan.error_message = (
                    f"Worker {scan.worker_id} died "
                    f"(last heartbeat: {scan.heartbeat_at})"
                )
                scan.completed_at = datetime.now(timezone.utc)
                reclaimed.append(str(scan.id))

            # 3. Remove dead worker records
            for wid in dead_ids:
                dead = await db.get(WorkerHeartbeat, wid)
                if dead is not None:
                    await db.delete(dead)

            await db.commit()
    except Exception as e:
        logger.error("Reaper cycle failed: %s", e)

    if reclaimed:
        logger.warning("Reaper reclaimed %d orphaned scans from %d dead worker(s)",
                       len(reclaimed), len(dead_ids))
    return reclaimed


async def start_reaper() -> asyncio.Task:
    """Start the background reaper task. Returns the task handle."""
    async def _reaper_loop():
        logger.info("Reaper started (interval=%ds, stall_timeout=%ds)",
                    REAPER_INTERVAL, STALL_TIMEOUT.total_seconds())
        while True:
            await asyncio.sleep(REAPER_INTERVAL)
            try:
                await reap_stale_workers()
            except Exception as e:
                logger.error("Reaper error: %s", e)

    return asyncio.create_task(_reaper_loop())
