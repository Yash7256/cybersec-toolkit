"""
ARQ-based distributed scan worker pool.

Architecture:
  FastAPI (producer)               ARQ Workers (consumers)
       │                                  │
       │  enqueue_job('scan_task', ...)   │
       ├─────────────────────────────────►│
       │                                  ├── AsyncPortScanner.scan()
       │                                  ├── store result in Redis
       │                                  │
       │  poll result from Redis          │
       │◄─────────────────────────────────┤
       │                                  │

Usage (worker):
  arq cybersec.core.arq_queue.WorkerSettings

Usage (API):
  from cybersec.core.arq_queue import enqueue_scan_job
  job = await enqueue_scan_job(target="...")
"""

import json
import logging
from typing import Optional

from arq import create_pool
from arq.connections import RedisSettings, ArqRedis
from arq.jobs import Job as ArqJob

from cybersec.config.settings import settings

logger = logging.getLogger(__name__)

RESULT_TTL = 3600  # 1 hour


# ── Pool ─────────────────────────────────────────────────────────────────────

_pool: Optional[ArqRedis] = None


async def get_pool() -> Optional[ArqRedis]:
    global _pool
    if _pool is None:
        try:
            _pool = await create_pool(
                RedisSettings.from_dsn(settings.REDIS_URL),
            )
        except Exception as e:
            logger.warning("ARQ pool creation failed: %s", e)
            return None
    return _pool


async def close_pool():
    global _pool
    if _pool is not None:
        try:
            await _pool.close()
        except Exception:
            pass
        _pool = None


# ── Producer ─────────────────────────────────────────────────────────────────

async def enqueue_scan_job(
    target: str,
    port_range: str = "common",
    scan_mode: str = "port",
    ip_version: str = "auto",
    user_id: str | None = None,
    options: dict | None = None,
) -> str | None:
    """Enqueue a scan job to the ARQ worker pool.

    Returns the job_id if successfully enqueued, None if ARQ unavailable.
    """
    pool = await get_pool()
    if pool is None:
        return None

    opts = dict(options or {})
    opts.setdefault("timeout", 3.0)
    opts.setdefault("rate_preset", "normal")

    job = await pool.enqueue_job(
        "scan_task",
        target,
        port_range,
        scan_mode,
        ip_version,
        opts,
        _job_try=1,
    )
    if job is None:
        logger.error("ARQ enqueue_job returned None for %s", target)
        return None

    logger.info("Enqueued scan job %s for %s", job.job_id, target)
    return job.job_id


async def get_job_status(job_id: str) -> dict:
    """Get the result of a completed ARQ job."""
    pool = await get_pool()
    if pool is None:
        return {"status": "unknown"}
    job = ArqJob(job_id=job_id, redis=pool)
    result = await job.result_info()
    if result is None:
        return {"status": "queued"}
    return {
        "status": result.success and "completed" or "failed",
        "result": result.result,
        "error": result.result if not result.success else None,
    }


# ── Worker task ──────────────────────────────────────────────────────────────

async def scan_task(
    ctx: dict,
    target: str,
    port_range: str,
    scan_mode: str,
    ip_version: str,
    opts: dict,
) -> dict:
    """ARQ worker task — runs a port scan in the worker process.

    This function runs inside an ARQ worker, which has its own asyncio event
    loop, its own process memory, and its own ephemeral port budget.

    Events are streamed to Redis Pub/Sub for real-time SSE delivery.
    """
    from cybersec.core.scanner import AsyncPortScanner
    from cybersec.core.events import publish_event

    logger.info("Worker starting scan: target=%s ports=%s mode=%s", target, port_range, scan_mode)

    job_id = ctx.get("job_id", "unknown")

    await publish_event(job_id, json.dumps({
        "type": "scan_start",
        "target": target,
        "port_range": port_range,
        "status": "running",
        "message": f"Worker scan started on {target}",
    }))

    scanner = AsyncPortScanner(
        timeout=opts.get("timeout", 3.0),
        rate_preset=opts.get("rate_preset", "normal"),
        rate_pps=opts.get("rate_pps"),
        enable_connection_pool=True,
    )

    async def on_port_found(port_result):
        evt = {
            "port": port_result.port,
            "protocol": port_result.protocol or "tcp",
            "state": port_result.state,
            "service": port_result.service.service_name if port_result.service else None,
            "version": port_result.service.service_version if port_result.service else None,
            "banner": port_result.banner,
            "risk_level": port_result.risk.risk_level if port_result.risk else "INFO",
            "risk_score": port_result.risk.risk_score if port_result.risk else 0.0,
            "cves": [
                {"id": c.id, "severity": c.severity, "cvss_score": c.cvss_score}
                for c in (port_result.cves or [])
            ],
        }
        await publish_event(job_id, json.dumps(evt))

    report = await scanner.scan(
        target,
        port_range,
        scan_mode=scan_mode,
        ip_version=ip_version,
        scan_callback=on_port_found,
    )

    result = {
        "status": "completed",
        "target": target,
        "ip": report.ip,
        "duration_seconds": report.scan_duration,
        "total_ports_scanned": report.total_ports_scanned,
        "open_ports_count": len(report.open_ports),
        "open_ports": [
            {
                "port": p.port,
                "protocol": p.protocol,
                "state": p.state,
                "service": p.service.service_name if p.service else None,
                "version": p.service.service_version if p.service else None,
                "banner": p.banner,
                "cves": [
                    {"id": c.id, "severity": c.severity, "cvss_score": c.cvss_score}
                    for c in (p.cves or [])
                ],
                "risk_level": p.risk.risk_level if p.risk else None,
                "risk_score": p.risk.risk_score if p.risk else None,
            }
            for p in report.open_ports
        ],
        "os_fingerprint": report.os_fingerprint,
    }

    await publish_event(job_id, json.dumps({
        "type": "scan_complete",
        "scan_duration": report.scan_duration,
        "total_open": len(report.open_ports),
    }))
    await publish_event(job_id, "[DONE]")

    logger.info("Worker completed job: target=%s open_ports=%d", target, len(report.open_ports))
    return result


# ── Worker settings (imported by `arq` CLI) ──────────────────────────────────

class WorkerSettings:
    functions = [scan_task]
    redis_settings = RedisSettings.from_dsn(settings.REDIS_URL)
    max_jobs = 4                     # concurrent scans per worker process
    job_timeout = 600                # 10 minutes max per scan
    keep_result = RESULT_TTL
    poll_delay = 0.5
