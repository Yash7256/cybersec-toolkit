"""
Producer — pushes scan jobs onto the Redis stream from the API process.
"""
import json
import logging
from uuid import uuid4

from cybersec.core.queue.backend import get_redis, SCAN_STREAM

logger = logging.getLogger(__name__)


async def enqueue_scan(
    target: str,
    port_range: str = "common",
    scan_mode: str = "port",
    ip_version: str = "auto",
    user_id: str | None = None,
    options: dict | None = None,
) -> str | None:
    """Push a scan job onto the Redis stream.

    Returns the job_id if Redis is available, None if fallback needed.
    """
    r = await get_redis()
    if r is None:
        return None

    job_id = str(uuid4())
    body = {
        "job_id": job_id,
        "target": target,
        "port_range": port_range,
        "scan_mode": scan_mode,
        "ip_version": ip_version,
        "user_id": user_id or "",
        "options": json.dumps(options or {}),
        "submitted_at": __import__("time").time(),
    }

    await r.xadd(SCAN_STREAM, body, maxlen=10_000)
    logger.info("Enqueued scan job %s for target %s", job_id, target)
    return job_id


async def get_job_result(job_id: str) -> dict | None:
    """Poll for a completed job result from Redis."""
    r = await get_redis()
    if r is None:
        return None

    raw = await r.get(f"scan_result:{job_id}")
    if raw is None:
        return None
    return json.loads(raw)
