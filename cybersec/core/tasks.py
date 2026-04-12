"""
Celery tasks for CyberSec.
"""
from celery import Celery
from cybersec.config import settings

celery_app = Celery(
    "cybersec",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
    include=["cybersec.core.tasks"]
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
)

@celery_app.task
def scan_target(target: str, port_range: str = "common"):
    """Async task to scan a target."""
    from cybersec.core.scanner import AsyncPortScanner
    scanner = AsyncPortScanner()
    report = scanner.scan(target, port_range)
    return {
        "target": report.target,
        "ip": report.ip,
        "total_ports_scanned": report.total_ports_scanned,
        "open_ports": len(report.open_ports),
        "scan_duration": report.scan_duration,
    }