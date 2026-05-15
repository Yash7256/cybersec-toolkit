import asyncio

from fastapi import HTTPException

from cybersec.runtime import job_store
from cybersec.runtime.scan_queue import get_queue_stats, scan_queue
from cybersec.runtime.scan_workers import get_worker_pool


async def get_queue_and_worker_stats() -> dict:
    stats = await get_queue_stats()
    pool = await get_worker_pool()

    return {
        "queue": stats,
        "workers": {
            "running": pool.is_running,
            "count": pool.worker_count,
        },
    }


async def submit_scan_job(target: str, port_range: str, timeout: float, rate_preset: str) -> dict:
    pool = await get_worker_pool()

    if not pool.is_running:
        raise HTTPException(status_code=503, detail="Scanner unavailable")

    stats = await get_queue_stats()
    if stats["full"] or stats["size"] > 800:
        raise HTTPException(status_code=429, detail="Server overloaded")

    job_id = job_store.create_job(
        target=target,
        port_range=port_range,
        opts={
            "timeout": timeout,
            "rate_preset": rate_preset,
        },
    )
    job_store.update_job(job_id, status=job_store.JobStatus.QUEUED)

    try:
        scan_queue.put_nowait(
            {
                "job_id": job_id,
                "target": target,
                "port_range": port_range,
                "opts": {"timeout": timeout, "rate_preset": rate_preset},
                "future": None,
            }
        )
    except asyncio.QueueFull:
        job_store.update_job(job_id, status=job_store.JobStatus.FAILED, error="Queue full")
        raise HTTPException(status_code=503, detail="Queue full")

    return {"job_id": job_id, "status": "queued"}


def get_job_or_404(job_id: str) -> dict:
    job = job_store.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


def get_ready_job_result(job_id: str) -> dict:
    job = get_job_or_404(job_id)

    if job["status"] == job_store.JobStatus.PENDING:
        raise HTTPException(status_code=202, detail="Job pending")
    if job["status"] == job_store.JobStatus.QUEUED:
        raise HTTPException(status_code=202, detail="Job queued")
    if job["status"] == job_store.JobStatus.RUNNING:
        raise HTTPException(status_code=202, detail="Job running")
    if job["status"] == job_store.JobStatus.FAILED:
        raise HTTPException(status_code=500, detail=job.get("error", "Job failed"))

    return job.get("result", {})


def list_scan_jobs(limit: int = 100) -> list[dict]:
    return job_store.list_jobs(limit=limit)
