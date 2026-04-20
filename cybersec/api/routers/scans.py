"""
Scans router — full implementation.

DB-OPTIONAL: Scans work even when PostgreSQL is unavailable.
Results are stored in-memory when DB is unreachable.
"""
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, WebSocket
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from typing import Optional, List, Literal
from uuid import UUID, uuid4

router = APIRouter(tags=["scans"])


@router.get("/health")
async def health_check():
    """Health check endpoint - doesn't require DB."""
    return {"status": "ok", "storage": "database"}


"""
Handles scan creation (runs AsyncPortScanner in background task),
real-time SSE streaming, status polling, OS fingerprint, and results retrieval.

DB-OPTIONAL: Scans work even when PostgreSQL is unavailable.
Results are stored in-memory when DB is unreachable.
"""
import asyncio
import json
import dataclasses
import logging
from datetime import datetime, timezone
from typing import Optional, List
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, WebSocket
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from typing import Literal
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cybersec.api.deps import get_db, get_optional_user
from cybersec.database.models import Scan, ScanResult, ToolResult, User
from cybersec.database.session import async_session_maker
from cybersec.core.scanner import AsyncPortScanner
from cybersec.core.utils import resolve_target, expand_target_range

logger = logging.getLogger(__name__)

# ─── In-memory scan stores (used when DB is unavailable) ──────────────────
# Stores scan metadata keyed by scan_id string
_scan_meta: dict[str, dict] = {}
# Stores full results keyed by scan_id string
_scan_results: dict[str, list[dict]] = {}
# Progress tracking
_scan_progress: dict[str, dict] = {}
# SSE event queues
_scan_events: dict[str, asyncio.Queue] = {}


def _safe_text(text: str | None) -> str | None:
    """Remove NULL bytes that cause PostgreSQL UTF-8 errors."""
    if text is None:
        return None
    return text.replace("\x00", "")


# ─── Schemas ────────────────────────────────────────────────────────────────

class ScanCreate(BaseModel):
    """Request model for creating a single-host port scan.
    
    Example:
    ```json
    {
        "target": "192.168.1.1",
        "port_range": "1-1000",
        "scan_type": "connect",
        "timeout": 3.0,
        "concurrency": 500,
        "rate_preset": "normal",
        "retry_config": {
            "max_retries": 3,
            "base_delay": 0.5,
            "backoff_multiplier": 2.0,
            "max_delay": 5.0
        }
    }
    ```
    """
    target: str = Field(
        min_length=1, 
        max_length=255,
        description="Target IP address, hostname, or domain to scan",
        examples=["192.168.1.1", "example.com", "scanme.nmap.org"]
    )
    port_range: str = Field(
        default="common",
        description="Port range specification. Options: 'common', 'top1000', 'all', or custom range like '1-1000' or '80,443,8080'",
        examples=["common", "top1000", "1-1000", "80,443,8080"]
    )
    scan_type: Literal[
        "connect", "syn", "udp",
        "stealth_fin", "stealth_null", "stealth_xmas", "stealth_ack",
        "zombie", "ack", "full", "port"
    ] = Field(
        default="port",
        description="Scanning technique to use. 'port' uses automatic mode selection",
        examples=["connect", "syn", "udp", "stealth_fin", "zombie"]
    )
    timeout: Optional[float] = Field(
        default=3.0,
        ge=0.1,
        le=30.0,
        description="Connection timeout in seconds for each port probe",
        examples=[1.0, 3.0, 5.0]
    )
    concurrency: Optional[int] = Field(
        default=500,
        ge=1,
        le=2000,
        description="Maximum concurrent connections for TCP scans",
        examples=[100, 500, 1000]
    )
    rate_preset: str = Field(
        default="normal",
        description="Rate limiting preset. Options: 'stealth' (100 pps), 'normal' (1000 pps), 'aggressive' (5000 pps)",
        examples=["stealth", "normal", "aggressive"]
    )
    rate_pps: Optional[float] = Field(
        default=None,
        ge=1.0,
        le=10000.0,
        description="Custom rate limit in packets per second. Overrides rate_preset if specified",
        examples=[100.0, 1000.0, 5000.0]
    )
    retry_config: Optional[dict] = Field(
        default=None,
        description="Retry configuration for failed probes. Defaults to 3 retries with exponential backoff",
        examples=[
            {
                "max_retries": 3,
                "base_delay": 0.5,
                "backoff_multiplier": 2.0,
                "max_delay": 5.0
            }
        ]
    )
    options: Optional[dict] = Field(
        default=None,
        description="Additional scan options (advanced usage)",
        examples=[{"verbose": True, "save_to_db": True}]
    )
    host_concurrency_limit: int = Field(
        default=10,
        ge=1,
        le=100,
        description="Maximum concurrent hosts for multi-host scans (deprecated, use concurrency instead)"
    )
    
class MultiHostScanCreate(BaseModel):
    """Request model for creating a multi-host port scan.
    
    Example:
    ```json
    {
        "targets": ["192.168.1.1", "192.168.1.2", "example.com"],
        "port_range": "1-1000",
        "scan_type": "connect",
        "timeout": 3.0,
        "concurrency": 500,
        "rate_preset": "normal",
        "host_concurrency_limit": 5,
        "retry_config": {
            "max_retries": 3,
            "base_delay": 0.5,
            "backoff_multiplier": 2.0,
            "max_delay": 5.0
        }
    }
    ```
    """
    targets: List[str] = Field(
        min_items=1,
        max_items=1000,
        description="List of targets to scan. Supports IP addresses, hostnames, and CIDR ranges",
        examples=[
            ["192.168.1.1", "192.168.1.2"],
            ["example.com", "scanme.nmap.org"],
            ["192.168.1.0/24", "10.0.0.0/30"]
        ]
    )
    port_range: str = Field(
        default="common",
        description="Port range specification. Options: 'common', 'top1000', 'all', or custom range like '1-1000' or '80,443,8080'",
        examples=["common", "top1000", "1-1000", "80,443,8080"]
    )
    scan_type: Literal[
        "connect", "syn", "udp",
        "stealth_fin", "stealth_null", "stealth_xmas", "stealth_ack",
        "zombie", "ack", "full", "port"
    ] = Field(
        default="port",
        description="Scanning technique to use. 'port' uses automatic mode selection",
        examples=["connect", "syn", "udp", "stealth_fin", "zombie"]
    )
    timeout: Optional[float] = Field(
        default=3.0,
        ge=0.1,
        le=30.0,
        description="Connection timeout in seconds for each port probe",
        examples=[1.0, 3.0, 5.0]
    )
    concurrency: Optional[int] = Field(
        default=500,
        ge=1,
        le=2000,
        description="Maximum concurrent connections for TCP scans",
        examples=[100, 500, 1000]
    )
    rate_preset: str = Field(
        default="normal",
        description="Rate limiting preset. Options: 'stealth' (100 pps), 'normal' (1000 pps), 'aggressive' (5000 pps)",
        examples=["stealth", "normal", "aggressive"]
    )
    rate_pps: Optional[float] = Field(
        default=None,
        ge=1.0,
        le=10000.0,
        description="Custom rate limit in packets per second. Overrides rate_preset if specified",
        examples=[100.0, 1000.0, 5000.0]
    )
    host_concurrency_limit: int = Field(
        default=10,
        ge=1,
        le=100,
        description="Maximum number of hosts to scan concurrently",
        examples=[5, 10, 20]
    )
    retry_config: Optional[dict] = Field(
        default=None,
        description="Retry configuration for failed probes. Defaults to 3 retries with exponential backoff",
        examples=[
            {
                "max_retries": 3,
                "base_delay": 0.5,
                "backoff_multiplier": 2.0,
                "max_delay": 5.0
            }
        ]
    )
    options: Optional[dict] = Field(
        default=None,
        description="Additional scan options (advanced usage)",
        examples=[{"verbose": True, "save_to_db": True}]
    )

class OSFingerprintRequest(BaseModel):
    target: str = Field(min_length=1, max_length=255)
    port_range: str = Field(default="common")
    scan_type: str = Field(default="port")
    options: Optional[dict] = None


class OSFingerprintRequest(BaseModel):
    target: str = Field(min_length=1, max_length=255)


def _build_evt(port_result) -> dict:
    """Build a serializable port result event dict."""
    cves_data = []
    if port_result.cves:
        for c in port_result.cves:
            cves_data.append({
                "id": c.id, "severity": c.severity,
                "cvss_score": c.cvss_score, "description": c.description
            })
    mitre_names = {
        "T1021.004": "SSH Remote Services",
        "T1021.001": "RDP Remote Services",
        "T1021.002": "SMB/Windows Admin Shares",
        "T1040": "Network Sniffing",
        "T1071.002": "FTP/Application Layer Protocol",
        "T1071.001": "HTTP/HTTPS Application Layer Protocol",
        "T1190": "Exploit Public-Facing Application",
        "T1210": "Exploitation of Remote Services",
        "T1133": "External Remote Services",
    }
    mitre_info = []
    if port_result.risk and port_result.risk.mitre_techniques:
        for technique in port_result.risk.mitre_techniques:
            mitre_info.append({
                "id": technique,
                "name": mitre_names.get(technique, "Unknown Technique"),
                "tactics": ["Lateral Movement"] if "T1021" in technique
                    else (["Initial Access"] if technique == "T1190" else ["Command and Control"]),
            })
    return {
        "port": port_result.port,
        "protocol": port_result.protocol,
        "state": port_result.state,
        "service": port_result.service.name if port_result.service else None,
        "version": port_result.service.version if port_result.service else None,
        "banner": _safe_text(port_result.banner),
        "risk_level": port_result.risk.risk_level if port_result.risk else "INFO",
        "risk_score": port_result.risk.risk_score if port_result.risk else 0.0,
        "cves": cves_data,
        "mitre_techniques": mitre_info,
    }


async def _persist_scan_results(
    db_scan_id: str | None,
    results_buffer: list[tuple],
    status: str,
    error: str | None = None
) -> None:
    """Persist scan results to DB if available; silently skip on failure."""
    if not db_scan_id:
        return
    try:
        async with async_session_maker() as db:
            scan_row = await db.get(Scan, db_scan_id)
            if scan_row:
                if status == "completed":
                    for port_res, _ in results_buffer:
                        cves_list = [
                            {"id": c.id, "severity": c.severity, "cvss_score": c.cvss_score}
                            for c in (port_res.cves or [])
                        ]
                        db.add(ScanResult(
                            scan_id=scan_row.id,
                            port=port_res.port,
                            protocol=port_res.protocol or "tcp",
                            state=port_res.state or "open",
                            service=port_res.service.name if port_res.service else None,
                            version=port_res.service.version if port_res.service else None,
                            banner=_safe_text(port_res.banner),
                            cves=cves_list,
                        ))
                    scan_row.status = "completed"
                    scan_row.completed_at = datetime.now(timezone.utc)
                elif status == "failed":
                    opts = scan_row.options or {}
                    opts["error"] = error
                    scan_row.options = opts
                    scan_row.status = "failed"
                await db.commit()
    except Exception as e:
        logger.warning("Failed to persist scan results to DB (scan=%s): %s", db_scan_id, e)


# ─── Background scan tasks ────────────────────────────────────────────────────

async def _run_multi_host_scan(
    scan_id: str,
    targets: List[str],
    port_range: str,
    db_scan_id: str | None = None,
    user_id: str | None = None,
    host_concurrency_limit: int = 10,
    scan_mode: str = "port",
    options: Optional[dict] = None
) -> None:
    """Runs multi-host scan in a background task.
    
    Supports CIDR ranges, IP ranges, and multiple individual targets.
    Stores results in-memory always, and additionally persists to DB
    if db_scan_id is provided and DB is reachable.
    """
    progress = {"status": "running", "progress_pct": 0, "hosts_scanned": 0, "total_hosts": 0}
    _scan_progress[scan_id] = progress
    _scan_events[scan_id] = asyncio.Queue()
    
    # Store scan metadata
    _scan_meta[scan_id] = {
        "targets": targets,
        "port_range": port_range,
        "scan_type": "multi_host",
        "status": "running",
        "user_id": user_id,
        "db_scan_id": db_scan_id,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "completed_at": None,
        "error": None,
        "host_concurrency_limit": host_concurrency_limit,
        "options": options or {}
    }
    _scan_results[scan_id] = []

    # Emit scan-start event
    await _scan_events[scan_id].put(json.dumps({
        "type": "multi_host_scan_start",
        "targets": targets,
        "port_range": port_range,
        "status": "running",
        "message": f"Multi-host scan started on {len(targets)} targets",
        "host_concurrency_limit": host_concurrency_limit
    }))

    results_buffer = []
    last_heartbeat = asyncio.get_event_loop().time()
    heartbeat_interval = 10.0

    async def _emit_heartbeat() -> None:
        nonlocal last_heartbeat
        now = asyncio.get_event_loop().time()
        if now - last_heartbeat >= heartbeat_interval:
            last_heartbeat = now
            await _scan_events[scan_id].put(json.dumps({
                "type": "heartbeat",
                "status": "running",
                "hosts_scanned": progress["hosts_scanned"],
                "total_hosts": progress["total_hosts"],
                "message": "Multi-host scan in progress...",
            }))

    async def on_host_port_found(target: str, port_result) -> None:
        """Callback for when a port is found on any host."""
        evt = _build_evt(port_result)
        evt["target"] = target  # Add target to event
        results_buffer.append((target, port_result, evt))
        _scan_results[scan_id].append(evt)
        await _scan_events[scan_id].put(json.dumps(evt))

    async def _heartbeat_loop() -> None:
        while True:
            await asyncio.sleep(10.0)
            if progress["status"] in ("completed", "failed"):
                break
            try:
                await _scan_events[scan_id].put(json.dumps({
                    "type": "heartbeat",
                    "status": progress["status"],
                    "progress_pct": progress["progress_pct"],
                    "hosts_scanned": progress["hosts_scanned"],
                    "total_hosts": progress["total_hosts"],
                    "message": f"Multi-host scan running... ({progress['hosts_scanned']}/{progress['total_hosts']} hosts scanned)",
                }))
            except Exception:
                break

    heartbeat_task = asyncio.create_task(_heartbeat_loop())

    try:
        # Parse retry configuration from options
        retry_config = None
        if options and "retry_config" in options:
            retry_opts = options["retry_config"]
            from cybersec.core.scanner import RetryConfig
            retry_config = RetryConfig(
                max_retries=retry_opts.get("max_retries", 3),
                base_delay=retry_opts.get("base_delay", 0.5),
                backoff_multiplier=retry_opts.get("backoff_multiplier", 2.0),
                max_delay=retry_opts.get("max_delay", 5.0)
            )
        
        # Parse rate configuration from options
        rate_preset = options.get("rate_preset", "normal") if options else "normal"
        rate_pps = options.get("rate_pps") if options else None
        
        scanner = AsyncPortScanner(
            timeout=3.0, 
            verbose=options.get("verbose", False) if options else False,
            retry_config=retry_config,
            rate_preset=rate_preset,
            rate_pps=rate_pps
        )
        
        # Run multi-host scan
        multi_report = await scanner.scan_multiple_hosts(
            targets=targets,
            port_range=port_range,
            scan_callback=on_host_port_found,
            scan_mode=scan_mode,
            host_concurrency_limit=host_concurrency_limit,
            verbose=options.get("verbose", False) if options else False
        )

        progress["progress_pct"] = 100
        progress["status"] = "completed"
        progress["hosts_scanned"] = multi_report.total_hosts_scanned
        progress["total_hosts"] = multi_report.total_hosts_scanned

        # Update metadata
        _scan_meta[scan_id].update({
            "status": "completed",
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "overall_scan_duration": multi_report.overall_scan_duration,
            "total_hosts_scanned": multi_report.total_hosts_scanned,
            "total_hosts_with_open_ports": multi_report.total_hosts_with_open_ports,
            "total_open_ports_found": multi_report.total_open_ports_found,
            "errors": multi_report.errors,
            "retry_stats": {
                "total_retries": multi_report.retry_stats.total_retries if multi_report.retry_stats else 0,
                "timeout_retries": multi_report.retry_stats.timeout_retries if multi_report.retry_stats else 0,
                "connection_reset_retries": multi_report.retry_stats.connection_reset_retries if multi_report.retry_stats else 0,
                "host_unreachable_failures": multi_report.retry_stats.host_unreachable_failures if multi_report.retry_stats else 0,
                "permission_denied_failures": multi_report.retry_stats.permission_denied_failures if multi_report.retry_stats else 0,
                "hard_failures": multi_report.retry_stats.hard_failures if multi_report.retry_stats else 0
            }
        })

        # Convert host reports to serializable format
        host_results = []
        for host_report in multi_report.host_reports:
            if host_report.scan_report:
                host_data = {
                    "target": host_report.target,
                    "ip": host_report.ip,
                    "total_ports_scanned": host_report.total_ports_scanned,
                    "open_ports_count": host_report.open_ports_count,
                    "scan_duration": host_report.scan_duration,
                    "error": host_report.error,
                    "ports": [_build_evt(port) for port in host_report.scan_report.open_ports]
                }
            else:
                host_data = {
                    "target": host_report.target,
                    "ip": host_report.ip,
                    "total_ports_scanned": host_report.total_ports_scanned,
                    "open_ports_count": host_report.open_ports_count,
                    "scan_duration": host_report.scan_duration,
                    "error": host_report.error,
                    "ports": []
                }
            host_results.append(host_data)

        # Store host results in scan metadata for retrieval
        _scan_meta[scan_id]["host_results"] = host_results

        await _persist_multi_host_scan_results(db_scan_id, results_buffer, "completed")

        summary_event = {
            "type": "multi_host_scan_complete",
            "overall_scan_duration": multi_report.overall_scan_duration,
            "total_hosts_scanned": multi_report.total_hosts_scanned,
            "total_hosts_with_open_ports": multi_report.total_hosts_with_open_ports,
            "total_open_ports_found": multi_report.total_open_ports_found,
            "host_concurrency_limit": host_concurrency_limit,
            "errors": multi_report.errors
        }
        await _scan_events[scan_id].put(json.dumps(summary_event))

    except Exception as e:
        error_msg = f"{e.__class__.__name__}: {e}"
        progress["status"] = "failed"
        progress["error"] = error_msg
        _scan_meta[scan_id]["status"] = "failed"
        _scan_meta[scan_id]["error"] = error_msg
        logger.exception("Multi-host scan %s failed for targets %s", scan_id, targets)
        await _persist_multi_host_scan_results(db_scan_id, results_buffer, "failed", error_msg)
    finally:
        heartbeat_task.cancel()
        try:
            await heartbeat_task
        except asyncio.CancelledError:
            pass
        await _scan_events[scan_id].put("[DONE]")


async def _persist_multi_host_scan_results(
    db_scan_id: str | None,
    results_buffer: List[tuple],
    status: str,
    error: str | None = None
) -> None:
    """Persist multi-host scan results to DB if available."""
    if not db_scan_id:
        return
    try:
        async with async_session_maker() as db:
            scan_row = await db.get(Scan, db_scan_id)
            if scan_row:
                if status == "completed":
                    # Group results by host for storage
                    host_results = {}
                    for target, port_res, _ in results_buffer:
                        if target not in host_results:
                            host_results[target] = []
                        host_results[target].append(port_res)
                    
                    # Store results for each host
                    for target, port_results in host_results.items():
                        for port_res in port_results:
                            cves_list = [
                                {"id": c.id, "severity": c.severity, "cvss_score": c.cvss_score}
                                for c in (port_res.cves or [])
                            ]
                            db.add(ScanResult(
                                scan_id=scan_row.id,
                                port=port_res.port,
                                protocol=port_res.protocol or "tcp",
                                state=port_res.state or "open",
                                service=port_res.service.name if port_res.service else None,
                                version=port_res.service.version if port_res.service else None,
                                banner=_safe_text(port_res.banner),
                                cves=cves_list,
                                target_host=target  # Add target host to distinguish multi-host results
                            ))
                    scan_row.status = "completed"
                    scan_row.completed_at = datetime.now(timezone.utc)
                elif status == "failed":
                    opts = scan_row.options or {}
                    opts["error"] = error
                    scan_row.options = opts
                    scan_row.status = "failed"
                await db.commit()
    except Exception as e:
        logger.warning("Failed to persist multi-host scan results to DB (scan=%s): %s", db_scan_id, e)


async def _run_scan(
    scan_id: str,
    target: str,
    port_range: str,
    resolved_ip: str | None = None,
    db_scan_id: str | None = None,
    user_id: str | None = None,
    options: dict | None = None,
) -> None:
    """Runs the actual port scan in a background task.

    Stores results in-memory always, and additionally persists to DB
    if db_scan_id is provided and DB is reachable.

    Emits heartbeat events every ~10s to keep Azure's load balancer connection alive.
    """
    progress = {"status": "running", "progress_pct": 0, "open_ports_found": 0}
    _scan_progress[scan_id] = progress
    _scan_events[scan_id] = asyncio.Queue()
    _scan_meta[scan_id] = {
        "target": target,
        "port_range": port_range,
        "resolved_ip": resolved_ip,
        "scan_type": "port",
        "status": "running",
        "user_id": user_id,
        "db_scan_id": db_scan_id,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "completed_at": None,
        "error": None,
    }
    _scan_results[scan_id] = []

    # Emit scan-start heartbeat so client knows scan is alive
    await _scan_events[scan_id].put(json.dumps({
        "type": "scan_start",
        "target": target,
        "port_range": port_range,
        "status": "running",
        "message": f"Scan started on {target}",
    }))

    results_buffer = []
    last_heartbeat = asyncio.get_event_loop().time()
    heartbeat_interval = 10.0  # seconds — keeps Azure LB connection alive

    async def _emit_heartbeat() -> None:
        """Emit a heartbeat event if enough time has passed."""
        nonlocal last_heartbeat
        now = asyncio.get_event_loop().time()
        if now - last_heartbeat >= heartbeat_interval:
            last_heartbeat = now
            await _scan_events[scan_id].put(json.dumps({
                "type": "heartbeat",
                "status": "running",
                "open_ports_found": progress["open_ports_found"],
                "message": "Scan in progress...",
            }))

    async def on_port_found(port_result) -> None:
        # Only increment open_ports_found for open ports
        if port_result.state == "open":
            progress["open_ports_found"] += 1
        evt = _build_evt(port_result)
        results_buffer.append((port_result, evt))
        _scan_results[scan_id].append(evt)
        await _scan_events[scan_id].put(json.dumps(evt))

    async def _heartbeat_loop() -> None:
        """Background heartbeat: emits events every 10s so Azure LB never times out."""
        while True:
            await asyncio.sleep(10.0)
            if progress["status"] in ("completed", "failed"):
                break
            try:
                await _scan_events[scan_id].put(json.dumps({
                    "type": "heartbeat",
                    "status": progress["status"],
                    "progress_pct": progress["progress_pct"],
                    "open_ports_found": progress["open_ports_found"],
                    "message": f"Scan running... ({progress['open_ports_found']} open ports found)",
                }))
            except Exception:
                break

    heartbeat_task = asyncio.create_task(_heartbeat_loop())

    try:
        # Parse rate configuration from options
        rate_preset = options.get("rate_preset", "normal") if options else "normal"
        rate_pps = options.get("rate_pps") if options else None
        
        scanner = AsyncPortScanner(
            timeout=3.0,
            rate_preset=rate_preset,
            rate_pps=rate_pps,
            enable_connection_pool=False
        )
        report = await scanner.scan(target, port_range, scan_callback=on_port_found, resolved_ip=resolved_ip)

        progress["progress_pct"] = 100
        progress["status"] = "completed"

        _scan_meta[scan_id]["status"] = "completed"
        _scan_meta[scan_id]["completed_at"] = datetime.now(timezone.utc).isoformat()
        _scan_meta[scan_id]["scan_duration"] = round(report.scan_duration, 2)
        _scan_meta[scan_id]["avg_latency_ms"] = report.avg_latency_ms
        _scan_meta[scan_id]["peak_concurrency"] = report.peak_concurrency
        _scan_meta[scan_id]["total_open"] = len(report.open_ports)

        await _persist_scan_results(db_scan_id, results_buffer, "completed")

        summary_event = {
            "type": "scan_complete",
            "scan_duration": round(report.scan_duration, 2),
            "avg_latency_ms": report.avg_latency_ms,
            "peak_concurrency": report.peak_concurrency,
            "total_open": len(report.open_ports),
        }
        await _scan_events[scan_id].put(json.dumps(summary_event))

    except Exception as e:
        error_msg = f"{e.__class__.__name__}: {e}"
        progress["status"] = "failed"
        progress["error"] = error_msg
        _scan_meta[scan_id]["status"] = "failed"
        _scan_meta[scan_id]["error"] = error_msg
        logger.exception("Scan %s failed for target %s", scan_id, target)
        await _persist_scan_results(db_scan_id, results_buffer, "failed", error_msg)
    finally:
        heartbeat_task.cancel()
        try:
            await heartbeat_task
        except asyncio.CancelledError:
            pass
        await _scan_events[scan_id].put("[DONE]")


# ─── Endpoints ───────────────────────────────────────────────────────────────

@router.post("/")
async def create_scan(
    body: ScanCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_user),
):
    """Create a new port scan and kick off background scanner.
    
    Supports CIDR ranges, IP ranges, and single targets.
    DB-OPTIONAL: If database is unavailable, scan still runs
    using in-memory storage. The response includes a `storage` field
    indicating where results are stored.
    """
    try:
        # Check if target is a CIDR range or IP range
        if '/' in body.target or '-' in body.target:
            # Expand to multiple IPs and convert to multi-host scan
            expanded_targets = expand_target_range(body.target)
            if len(expanded_targets) == 1:
                # Single target after expansion, use regular scan
                resolved_ip = expanded_targets[0]
            else:
                # Multiple targets, create multi-host scan
                multi_body = MultiHostScanCreate(
                    targets=[body.target],
                    port_range=body.port_range,
                    scan_type=body.scan_type,
                    options=body.options,
                    host_concurrency_limit=body.host_concurrency_limit
                )
                return await create_multi_host_scan(multi_body, background_tasks, db, current_user)
        else:
            # Single target, resolve normally
            resolved_ip = resolve_target(body.target)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    db_scan_id: str | None = None
    storage = "memory"

    try:
        scan = Scan(
            user_id=current_user.id if current_user else None,
            target=body.target,
            scan_type=body.scan_type if body.scan_type else "port",
            status="running",
            port_range=body.port_range,
            options={**(body.options or {}), "resolved_ip": resolved_ip, "host_concurrency_limit": body.host_concurrency_limit},
            started_at=datetime.now(timezone.utc),
        )
        db.add(scan)
        await db.commit()
        await db.refresh(scan)
        db_scan_id = str(scan.id)
        storage = "database"
    except Exception as e:
        logger.warning("DB unavailable during scan creation (target=%s): %s", body.target, e)

    scan_id_str = str(db_scan_id) if db_scan_id else str(uuid4())
    background_tasks.add_task(
        _run_scan,
        scan_id_str,
        body.target,
        body.port_range,
        resolved_ip,
        db_scan_id,
        str(current_user.id) if current_user else None,
        body.options,
    )

    return {
        "id": scan_id_str,
        "scan_id": scan_id_str,
        "target": body.target,
        "status": "running",
        "port_range": body.port_range,
        "storage": storage,
        "note": "Results are streamed via /api/scans/{id}/stream" if storage == "memory"
            else None,
    }


@router.post("/multi-host")
async def create_multi_host_scan(
    body: MultiHostScanCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_user),
):
    """Create a new multi-host scan with CIDR range support.
    
    Supports multiple targets, CIDR ranges, and IP ranges.
    DB-OPTIONAL: If database is unavailable, scan still runs
    using in-memory storage.
    """
    # Validate all targets first
    invalid_targets = []
    for target in body.targets:
        try:
            expand_target_range(target)
        except ValueError as e:
            invalid_targets.append(f"{target}: {e}")
    
    if invalid_targets:
        raise HTTPException(
            status_code=422, 
            detail={"invalid_targets": invalid_targets}
        )

    db_scan_id: str | None = None
    storage = "memory"

    try:
        scan = Scan(
            user_id=current_user.id if current_user else None,
            target=", ".join(body.targets),  # Store as comma-separated for DB
            scan_type="multi_host",
            status="running",
            port_range=body.port_range,
            options={
                **(body.options or {}), 
                "targets": body.targets,
                "host_concurrency_limit": body.host_concurrency_limit
            },
            started_at=datetime.now(timezone.utc),
        )
        db.add(scan)
        await db.commit()
        await db.refresh(scan)
        db_scan_id = str(scan.id)
        storage = "database"
    except Exception as e:
        logger.warning("DB unavailable during multi-host scan creation (targets=%s): %s", body.targets, e)

    scan_id_str = str(db_scan_id) if db_scan_id else str(uuid4())
    background_tasks.add_task(
        _run_multi_host_scan,
        scan_id_str,
        body.targets,
        body.port_range,
        db_scan_id,
        str(current_user.id) if current_user else None,
        body.host_concurrency_limit,
        body.scan_type,
        body.options
    )

    return {
        "id": scan_id_str,
        "scan_id": scan_id_str,
        "targets": body.targets,
        "status": "running",
        "port_range": body.port_range,
        "scan_type": "multi_host",
        "host_concurrency_limit": body.host_concurrency_limit,
        "storage": storage,
        "note": "Results are streamed via /api/scans/{id}/stream" if storage == "memory"
            else None,
    }


@router.get("/{scan_id}/status")
async def get_scan_status(scan_id: str):
    """Return current status and progress for a scan.

    Checks in-memory stores first, then falls back to DB.
    """
    progress = _scan_progress.get(scan_id)
    meta = _scan_meta.get(scan_id)

    if progress or meta:
        return {
            "scan_id": scan_id,
            "status": progress.get("status", meta.get("status", "unknown")) if progress else meta.get("status", "unknown"),
            "progress_pct": progress.get("progress_pct", 0) if progress else (100 if meta and meta.get("status") == "completed" else 0),
            "open_ports_found": progress.get("open_ports_found", 0) if progress else len(_scan_results.get(scan_id, [])),
            "error": progress.get("error") or meta.get("error") if meta else None,
            "storage": "memory",
        }

    try:
        async with async_session_maker() as db:
            scan = await db.get(Scan, scan_id)
            if scan:
                return {
                    "scan_id": scan_id,
                    "status": scan.status,
                    "progress_pct": 100 if scan.status == "completed" else 0,
                    "open_ports_found": 0,
                    "error": (scan.options or {}).get("error"),
                    "storage": "database",
                }
    except Exception as e:
        logger.warning("Status lookup failed (scan_id=%s): %s", scan_id, e)

    raise HTTPException(status_code=404, detail="Scan not found")


@router.get("/{scan_id}/stream")
async def stream_scan_results(scan_id: str):
    """SSE stream delivering port results in real time as they are discovered.

    Works with both in-memory and DB-backed scans.
    Azure-compatible: keepalive every 55s (under 4-min LB timeout).
    """
    async def event_generator():
        queue = _scan_events.get(scan_id)
        if queue is None:
            yield "data: [DONE]\n\n"
            return

        while True:
            try:
                msg = await asyncio.wait_for(queue.get(), timeout=55.0)
            except asyncio.TimeoutError:
                yield ": keepalive\n\n"
                continue

            if msg == "[DONE]":
                yield "data: [DONE]\n\n"
                break
            yield f"data: {msg}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
            "Transfer-Encoding": "chunked",
        },
    )


def _generate_single_host_csv(results: List[dict]) -> str:
    """Generate CSV content for single-host scan results."""
    if not results:
        return "No open ports found\n"
    
    output = []
    output.append("target,port,protocol,state,service,version,cve_count,highest_cvss,risk_level\n")
    
    for result in results:
        port = result.get("port", "")
        protocol = result.get("protocol", "")
        state = result.get("state", "")
        service_info = result.get("service", {})
        service_name = service_info.get("name", "unknown")
        service_version = service_info.get("version", "")
        cves = result.get("cves", [])
        cve_count = len(cves)
        highest_cvss = max([cve.get("cvss_score", 0) for cve in cves]) if cves else 0.0
        risk_info = result.get("risk", {})
        risk_level = risk_info.get("risk_level", "INFO")
        
        target = result.get("target", "")
        
        output.append(f"{target},{port},{protocol},{state},\"{service_name}\",\"{service_version}\",{cve_count},{highest_cvss},{risk_level}")
    
    return "\n".join(output)

def _generate_multi_host_csv(host_results: List[dict]) -> str:
    """Generate CSV content for multi-host scan results."""
    if not host_results:
        return "No hosts scanned\n"
    
    output = []
    output.append("target,port,protocol,state,service,version,cve_count,highest_cvss,risk_level\n")
    
    for host_report in host_results:
        target = host_report.get("target", "")
        ports = host_report.get("ports", [])
        
        for port in ports:
            port_num = port.get("port", "")
            protocol = port.get("protocol", "")
            state = port.get("state", "")
            service_info = port.get("service", {})
            service_name = service_info.get("name", "unknown")
            service_version = service_info.get("version", "")
            cves = port.get("cves", [])
            cve_count = len(cves)
            highest_cvss = max([cve.get("cvss_score", 0) for cve in cves]) if cves else 0.0
            risk_info = port.get("risk", {})
            risk_level = risk_info.get("risk_level", "INFO")
            
            output.append(f"{target},{port_num},{protocol},{state},\"{service_name}\",\"{service_version}\",{cve_count},{highest_cvss},{risk_level}")
    
    return "\n".join(output)


@router.get("/{scan_id}")
async def get_scan(scan_id: str, format: str = "html"):
    """Return full scan details with all results.
    
    Supports format parameter:
    - ?format=json: Returns JSON response
    - ?format=csv: Returns CSV response
    - ?format=html: Returns HTML response (default)
    
    Checks in-memory stores first, then falls back to DB.
    Supports both single-host and multi-host scans.
    """
    meta = _scan_meta.get(scan_id)
    results = _scan_results.get(scan_id, [])

    if meta is not None:
        response = {
            "id": scan_id,
            "scan_type": meta.get("scan_type", "port"),
            "status": meta["status"],
            "port_range": meta.get("port_range"),
            "started_at": meta.get("started_at"),
            "completed_at": meta.get("completed_at"),
            "error": meta.get("error"),
            "storage": "memory",
        }
        
        if meta.get("scan_type") == "multi_host":
            # Multi-host scan specific fields
            response.update({
                "targets": meta.get("targets", []),
                "host_concurrency_limit": meta.get("host_concurrency_limit", 10),
                "total_hosts_scanned": meta.get("total_hosts_scanned", 0),
                "total_hosts_with_open_ports": meta.get("total_hosts_with_open_ports", 0),
                "total_open_ports_found": meta.get("total_open_ports_found", 0),
                "overall_scan_duration": meta.get("overall_scan_duration", 0),
                "host_results": meta.get("host_results", []),
                "errors": meta.get("errors", []),
                "results": results  # Also include flat results for compatibility
            })
        else:
            # Single-host scan
            response.update({
                "target": meta.get("target"),
                "results": results
            })
        
        # Handle format parameter
        if format.lower() == "json":
            from fastapi.responses import JSONResponse
            return JSONResponse(content=response)
        elif format.lower() == "csv":
            # Generate CSV content
            if meta.get("scan_type") == "multi_host":
                # Multi-host CSV
                csv_content = _generate_multi_host_csv(meta.get("host_results", []))
            else:
                # Single-host CSV  
                csv_content = _generate_single_host_csv(results)
            
            from fastapi.responses import Response
            return Response(
                content=csv_content,
                media_type="text/csv",
                headers={"Content-Disposition": f"attachment; filename=scan_{scan_id}.csv"}
            )
        else:
            # Default HTML response
            return response

    try:
        async with async_session_maker() as db:
            scan = await db.get(Scan, scan_id)
            if not scan:
                raise HTTPException(status_code=404, detail="Scan not found")

            results_q = await db.execute(
                select(ScanResult).where(ScanResult.scan_id == scan_id).order_by(ScanResult.port.asc())
            )
            db_results = results_q.scalars().all()

            from cybersec.core.port_analyzer import PortAnalyzer
            analyzer = PortAnalyzer()
            mitre_names = {
                "T1021.004": "SSH Remote Services",
                "T1021.001": "RDP Remote Services",
                "T1021.002": "SMB/Windows Admin Shares",
                "T1040": "Network Sniffing",
                "T1071.002": "FTP/Application Layer Protocol",
                "T1071.001": "HTTP/HTTPS Application Layer Protocol",
                "T1190": "Exploit Public-Facing Application",
                "T1210": "Exploitation of Remote Services",
                "T1133": "External Remote Services",
            }

            if scan.scan_type == "multi_host":
                # Group results by target host
                host_results = {}
                for r in db_results:
                    target_host = getattr(r, 'target_host', None) or scan.target
                    if target_host not in host_results:
                        host_results[target_host] = []
                    
                    cves = r.cves or []
                    risk = analyzer.analyze(r.port, [])
                    mitre_info = []
                    for technique in analyzer.MITRE_MAP.get(r.port, []):
                        mitre_info.append({
                            "id": technique,
                            "name": mitre_names.get(technique, "Unknown Technique"),
                            "tactics": ["Lateral Movement"] if "T1021" in technique
                                else (["Initial Access"] if technique == "T1190" else ["Command and Control"]),
                        })
                    
                    host_results[target_host].append({
                        "port": r.port,
                        "protocol": r.protocol,
                        "state": r.state,
                        "service": r.service,
                        "version": r.version,
                        "banner": r.banner,
                        "cves": cves,
                        "risk_level": risk.risk_level,
                        "risk_score": risk.risk_score,
                        "mitre_techniques": mitre_info,
                    })
                
                # Convert to expected format
                host_results_list = []
                total_open_ports = 0
                for target_host, ports in host_results.items():
                    host_results_list.append({
                        "target": target_host,
                        "ip": target_host,  # DB doesn't store resolved IP separately for multi-host
                        "total_ports_scanned": len(ports),
                        "open_ports_count": len(ports),
                        "scan_duration": 0,  # Not tracked separately in DB
                        "error": None,
                        "ports": ports
                    })
                    total_open_ports += len(ports)
                
                return {
                    "id": str(scan.id),
                    "targets": scan.target.split(", "),
                    "scan_type": scan.scan_type,
                    "status": scan.status,
                    "port_range": scan.port_range,
                    "started_at": scan.started_at.isoformat() if scan.started_at else None,
                    "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
                    "error": (scan.options or {}).get("error"),
                    "storage": "database",
                    "host_concurrency_limit": (scan.options or {}).get("host_concurrency_limit", 10),
                    "total_hosts_scanned": len(host_results_list),
                    "total_hosts_with_open_ports": len([h for h in host_results_list if h["open_ports_count"] > 0]),
                    "total_open_ports_found": total_open_ports,
                    "host_results": host_results_list,
                    "errors": [],
                    "results": [port for host_ports in host_results.values() for port in host_ports]  # Flat results
                }
            else:
                # Single-host scan (original logic)
                result_dicts = []
                for r in db_results:
                    cves = r.cves or []
                    risk = analyzer.analyze(r.port, [])
                    mitre_info = []
                    for technique in analyzer.MITRE_MAP.get(r.port, []):
                        mitre_info.append({
                            "id": technique,
                            "name": mitre_names.get(technique, "Unknown Technique"),
                            "tactics": ["Lateral Movement"] if "T1021" in technique
                                else (["Initial Access"] if technique == "T1190" else ["Command and Control"]),
                        })
                    result_dicts.append({
                        "port": r.port,
                        "protocol": r.protocol,
                        "state": r.state,
                        "service": r.service,
                        "version": r.version,
                        "banner": r.banner,
                        "cves": cves,
                        "risk_level": risk.risk_level,
                        "risk_score": risk.risk_score,
                        "mitre_techniques": mitre_info,
                    })

                return {
                    "id": str(scan.id),
                    "target": scan.target,
                    "scan_type": scan.scan_type,
                    "status": scan.status,
                    "port_range": scan.port_range,
                    "started_at": scan.started_at.isoformat() if scan.started_at else None,
                    "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
                    "error": (scan.options or {}).get("error"),
                    "storage": "database",
                    "results": result_dicts,
                }
    except HTTPException:
        raise
    except Exception as e:
        logger.warning("Get scan failed (scan_id=%s): %s", scan_id, e)
        raise HTTPException(status_code=503, detail="Database unavailable; please start Postgres")


@router.get("/")
async def list_scans(
    limit: int = 20,
    db: AsyncSession = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_user),
):
    """List recent scans from DB. Falls back to empty list if DB unavailable."""
    try:
        q = await db.execute(select(Scan).order_by(Scan.created_at.desc()).limit(limit))
        scans = q.scalars().all()
    except Exception as e:
        logger.warning("List scans failed due to DB error: %s", e)
        import traceback
        logger.warning("Trace: %s", traceback.format_exc())
        return {"scans": [], "storage": "database_unavailable", "error": str(e)}
    return {
        "scans": [
            {
                "id": str(s.id),
                "target": s.target,
                "scan_type": s.scan_type,
                "status": s.status,
                "port_range": s.port_range,
                "created_at": s.created_at.isoformat() if s.created_at else None,
            }
            for s in scans
        ],
        "storage": "database",
    }


# ─── OS Fingerprint ──────────────────────────────────────────────────────────

@router.post("/os-fingerprint")
async def os_fingerprint(
    body: OSFingerprintRequest,
    db: AsyncSession = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_user),
):
    """Run OS fingerprinting by scanning key ports and analyzing banners.

    DB-OPTIONAL: If DB is unavailable, still returns full results
    but tool_result_id will be None.
    """
    try:
        resolved_ip = resolve_target(body.target)
    except (ValueError, Exception) as e:
        raise HTTPException(status_code=422, detail=f"Cannot resolve target: {e}")

    scanner = AsyncPortScanner(timeout=3.0)
    report = await scanner.scan(body.target, port_range="22,80,135,139,445")

    banners = [
        r.service.banner
        for r in report.open_ports
        if r.service and r.service.banner
    ]

    from cybersec.core.os_fingerprint import OSFingerprinter
    fp = OSFingerprinter().fingerprint(banners, [r.port for r in report.open_ports])

    result_data = {
        "os_name": fp.os_name,
        "confidence": fp.confidence,
        "method": fp.method,
        "open_ports": [r.port for r in report.open_ports],
        "scan_duration": report.scan_duration,
    }
    tool_result_id = None

    try:
        tool_result = ToolResult(
            user_id=current_user.id if current_user else None,
            tool_name="os_fingerprint",
            target=body.target,
            result_data=result_data,
        )
        db.add(tool_result)
        await db.commit()
        await db.refresh(tool_result)
        tool_result_id = str(tool_result.id)
    except Exception as e:
        logger.warning("OS fingerprint DB save failed: %s", e)

    return {
        "target": body.target,
        "ip": report.ip,
        "os_name": fp.os_name,
        "confidence": fp.confidence,
        "confidence_pct": round(fp.confidence * 100, 1),
        "method": fp.method,
        "open_ports_scanned": [r.port for r in report.open_ports],
        "tool_result_id": tool_result_id,
        "storage": "database" if tool_result_id else "memory",
    }


@router.websocket("/ws/{scan_id}")
async def websocket_scan_progress(websocket: WebSocket, scan_id: str):
    await websocket.accept()
    try:
        if scan_id not in _scan_events:
            await websocket.send_json({"error": "Scan not found"})
            return

        queue = _scan_events[scan_id]
        while True:
            try:
                event = await asyncio.wait_for(queue.get(), timeout=30)
                await websocket.send_json(event)
            except asyncio.TimeoutError:
                await websocket.send_json({"type": "ping"})
    except Exception as e:
        logger.error("WebSocket error: %s", e)
    finally:
        await websocket.close()
