"""
Consumer — runs inside each worker process.
Reads scan jobs from Redis stream, executes the scan, publishes results.
"""
import asyncio
import json
import logging
import time

from cybersec.core.queue.backend import (
    get_redis,
    SCAN_STREAM,
    SCAN_GROUP,
    RESULT_PREFIX,
)

logger = logging.getLogger(__name__)


async def consume_scan_jobs(worker_id: int = 0):
    """Blocking loop: consume scan jobs from the Redis stream forever."""
    r = await get_redis()
    if r is None:
        logger.error("Redis unavailable — worker cannot start")
        return

    consumer_name = f"worker-{worker_id}"

    while True:
        try:
            # Block for up to 5 seconds waiting for new jobs
            results = await r.xreadgroup(
                groupname=SCAN_GROUP,
                consumername=consumer_name,
                streams={SCAN_STREAM: ">"},
                count=1,
                block=5_000,
            )

            if not results:
                continue

            for stream_name, messages in results:
                for msg_id, msg_data in messages:
                    await _process_job(msg_id, msg_data, r)
                    await r.xack(SCAN_STREAM, SCAN_GROUP, msg_id)

        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error("Consumer error: %s", e, exc_info=True)
            await asyncio.sleep(1)


async def _process_job(msg_id: str, msg: dict, r) -> None:
    """Process a single scan job."""
    job_id = msg.get("job_id", msg_id)
    target = msg.get("target", "")
    port_range = msg.get("port_range", "common")
    scan_mode = msg.get("scan_mode", "port")
    ip_version = msg.get("ip_version", "auto")
    options = json.loads(msg.get("options", "{}"))

    logger.info("Worker picked up job %s: target=%s ports=%s", job_id, target, port_range)

    # Mark as running
    await r.hset(f"{RESULT_PREFIX}{job_id}", mapping={
        "status": "running",
        "started_at": time.time(),
    })

    try:
        from cybersec.core.scanner import AsyncPortScanner

        scanner = AsyncPortScanner(
            timeout=options.get("timeout", 3.0),
            rate_preset=options.get("rate_preset", "normal"),
            rate_pps=options.get("rate_pps"),
            enable_connection_pool=False,
        )

        report = await scanner.scan(
            target,
            port_range,
            scan_mode=scan_mode,
            ip_version=ip_version,
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
            "completed_at": time.time(),
        }

        await r.set(f"{RESULT_PREFIX}{job_id}", json.dumps(result), ex=3600)
        logger.info("Job %s completed: %d open ports", job_id, len(report.open_ports))

    except asyncio.CancelledError:
        raise
    except Exception as e:
        logger.exception("Job %s failed", job_id)
        await r.set(
            f"{RESULT_PREFIX}{job_id}",
            json.dumps({"status": "failed", "error": str(e), "completed_at": time.time()}),
            ex=3600,
        )
