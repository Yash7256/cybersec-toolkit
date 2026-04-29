from typing import Dict, Optional
from datetime import datetime, timezone
import uuid

jobs: Dict[str, dict] = {}


class JobStatus:
    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


def create_job(
    target: str,
    port_range: str = "common",
    opts: Optional[dict] = None
) -> str:
    """Create a new job and return job ID."""
    job_id = str(uuid.uuid4())
    
    jobs[job_id] = {
        "id": job_id,
        "target": target,
        "port_range": port_range,
        "opts": opts or {},
        "status": JobStatus.PENDING,
        "created_at": datetime.now(timezone.utc),
        "started_at": None,
        "completed_at": None,
        "result": None,
        "error": None
    }
    
    return job_id


def get_job(job_id: str) -> Optional[dict]:
    """Get job by ID."""
    return jobs.get(job_id)


def update_job(
    job_id: str,
    status: Optional[str] = None,
    result: Optional[dict] = None,
    error: Optional[str] = None
) -> bool:
    """Update job status, result, or error."""
    job = jobs.get(job_id)
    if not job:
        return False
    
    if status:
        job["status"] = status
        if status == JobStatus.RUNNING and not job["started_at"]:
            job["started_at"] = datetime.now(timezone.utc)
        elif status in (JobStatus.COMPLETED, JobStatus.FAILED):
            job["completed_at"] = datetime.now(timezone.utc)
    
    if result is not None:
        job["result"] = result
    
    if error:
        job["error"] = error
    
    return True


def list_jobs(status_filter: Optional[str] = None, limit: int = 100) -> list:
    """List jobs, optionally filtered by status."""
    all_jobs = list(jobs.values())
    
    if status_filter:
        all_jobs = [j for j in all_jobs if j["status"] == status_filter]
    
    all_jobs.sort(key=lambda j: j["created_at"], reverse=True)
    return all_jobs[:limit]


def delete_job(job_id: str) -> bool:
    """Delete a job."""
    if job_id in jobs:
        del jobs[job_id]
        return True
    return False


def clear_jobs() -> None:
    """Clear all jobs."""
    jobs.clear()