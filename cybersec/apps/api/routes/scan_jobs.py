from fastapi import APIRouter
from pydantic import BaseModel

from cybersec.apps.api.services.scan_jobs import (
    get_job_or_404,
    get_queue_and_worker_stats,
    get_ready_job_result,
    list_scan_jobs,
    submit_scan_job,
)

router = APIRouter(tags=["scan-jobs"])


class QueueScanRequest(BaseModel):
    target: str
    port_range: str = "common"
    timeout: float = 3.0
    rate_preset: str = "normal"


class ScanSubmitRequest(BaseModel):
    target: str
    port_range: str = "common"
    timeout: float = 3.0
    rate_preset: str = "normal"


@router.get("/health")
async def health_check():
    return {"status": "ok", "storage": "database"}


@router.get("/queue/stats")
async def queue_stats():
    return await get_queue_and_worker_stats()


@router.post("/jobs")
async def submit_scan(req: ScanSubmitRequest):
    return await submit_scan_job(req.target, req.port_range, req.timeout, req.rate_preset)


@router.get("/jobs/{job_id}")
async def get_job_status(job_id: str):
    return get_job_or_404(job_id)


@router.get("/jobs/{job_id}/result")
async def get_job_result(job_id: str):
    return get_ready_job_result(job_id)


@router.get("/jobs")
async def list_jobs(limit: int = 100):
    return list_scan_jobs(limit=limit)
