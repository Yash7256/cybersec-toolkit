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

from fastapi import APIRouter, Depends, HTTPException, WebSocket
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from typing import Literal
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cybersec.apps.api.deps import get_db, get_optional_user, get_current_user
from cybersec.core.security.policy import validate_target_async, validate_targets, validate_port_count
from cybersec.core.security.throttle import check_submit_throttle
from cybersec.database.models import Scan, ScanResult, ToolResult, User
from cybersec.database.session import async_session_maker
from cybersec.core.scanner import AsyncPortScanner
from cybersec.core.scanner.utils import expand_target_range
from cybersec.core.queue.producer import enqueue_scan, get_job_result
from cybersec.core.arq_queue import enqueue_scan_job, get_job_status as get_arq_status
from cybersec.core.security.attack_mapping import enrich_scan_with_attack, map_cve_to_attack
from cybersec.core.security.nvd_client import CVEResult
from cybersec.core.scanner.analysis.service_detect import ServiceDetectionResult
from cybersec.apps.api.services.scan_state import (
    scan_events as _scan_events,
    scan_meta as _scan_meta,
    scan_progress as _scan_progress,
    scan_results as _scan_results,
    safe_queue_put,
    append_result,
    register_task,
    unregister_task,
    cleanup_scan,
    acquire_scan_slot,
    release_scan_slot,
    QUEUE_MAXSIZE,
    MAX_CONCURRENT_SCANS_GLOBAL,
    MAX_CONCURRENT_SCANS_PER_USER,
)
from cybersec.core.events import subscribe_events, unsubscribe_events

logger = logging.getLogger(__name__)
router = APIRouter(tags=["scans"])


def _safe_text(text: str | None) -> str | None:
    """Remove NULL bytes that cause PostgreSQL UTF-8 errors."""
    if text is None:
        return None
    return text.replace("\x00", "")


# ─── Schemas ────────────────────────────────────────────────────────────────

class ScanCreate(BaseModel):
    """Request model for creating a single-host port scan.

    Use a named profile for sensible defaults:
      {"target": "example.com", "port_range": "quick"}
      {"target": "db.internal", "port_range": "database"}

    Or use a raw port range:
      {"target": "example.com", "port_range": "80,443,8080"}
      {"target": "10.0.0.1", "port_range": "1-1000", "scan_type": "syn"}
    """
    target: str = Field(
        min_length=1, 
        max_length=255,
        description="Target IP address, hostname, or domain to scan",
        examples=["192.168.1.1", "example.com", "scanme.nmap.org"]
    )
    port_range: str = Field(
        default="quick",
        description="Scan profile (quick, web-audit, database, remote-access, full-tcp, stealth) or raw port spec (common, top1000, 1-1000, 80,443)",
        examples=["quick", "web-audit", "full-tcp", "common"]
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
        default=None,
        ge=0.1,
        le=30.0,
        description="Overrides profile connect timeout if set",
        examples=[1.0, 3.0, 5.0]
    )
    concurrency: Optional[int] = Field(
        default=None,
        ge=1,
        le=2000,
        description="Overrides profile concurrency if set",
        examples=[100, 500, 1000]
    )
    rate_preset: Optional[str] = Field(
        default=None,
        description="Overrides profile rate preset if set. Options: stealth (100 pps), normal (1000 pps), aggressive (5000 pps)",
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
    ip_version: Literal["auto", "ipv4", "ipv6"] = Field(
        default="auto",
        description="IP version preference: 'ipv4', 'ipv6', or 'auto' (prefer v4, fall back v6)",
        examples=["auto", "ipv4", "ipv6"]
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
    ip_version: Literal["auto", "ipv4", "ipv6"] = Field(
        default="auto",
        description="IP version preference: 'ipv4', 'ipv6', or 'auto' (prefer v4, fall back v6)",
        examples=["auto", "ipv4", "ipv6"]
    )
    options: Optional[dict] = Field(
        default=None,
        description="Additional scan options (advanced usage)",
        examples=[{"verbose": True, "save_to_db": True}]
    )

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
        "T1110": "Brute Force",
        "T1078": "Valid Accounts",
        "T1571": "Non-Standard Port",
        "T1048.003": "Exfiltration Over Unencrypted Protocol",
        "T1083": "File and Directory Discovery",
        "T1566.001": "Spearphishing Attachment",
        "T1592": "Gather Victim Host Information",
        "T1071.004": "DNS Application Layer Protocol",
        "T1059.007": "JavaScript Command and Scripting Interpreter",
        "T1595.002": "Web Vulnerability Scanning",
        "T1048.002": "Exfiltration Over C2 Channel",
    }
    mitre_info = []
    if port_result.risk and port_result.risk.mitre_techniques:
        for technique in port_result.risk.mitre_techniques:
            mitre_info.append({
                "id": technique,
                "name": mitre_names.get(technique, "Unknown Technique"),
                "tactics": (
                    ["Lateral Movement"] if "T1021" in technique
                    else (["Initial Access"] if technique == "T1190"
                    else (["Credential Access"] if technique == "T1110"
                    else (["Initial Access"] if technique == "T1078"
                    else (["Defense Evasion"] if technique == "T1571"
                    else (["Exfiltration"] if technique.startswith("T1048")
                    else (["Discovery"] if technique in ["T1083", "T1592"]
                    else (["Reconnaissance"] if technique in ["T1566.001", "T1595.002"]
                    else (["Command and Control"] if technique.startswith("T1071")
                    else (["Execution"] if technique == "T1059.007"
                    else ["Unknown"]))))))))))
            })
    return {
        "port": port_result.port,
        "protocol": port_result.protocol,
        "state": port_result.state,
        "service": port_result.service.service_name if port_result.service else None,
        "version": port_result.service.service_version if port_result.service else None,
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
    _scan_events[scan_id] = asyncio.Queue(maxsize=QUEUE_MAXSIZE)
    
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
    await safe_queue_put(scan_id, json.dumps({
        "type": "multi_host_scan_start",
        "targets": targets,
        "port_range": port_range,
        "status": "running",
        "message": f"Multi-host scan started on {len(targets)} targets",
        "host_concurrency_limit": host_concurrency_limit
    }))

    results_buffer: list = []
    BUFFER_LIMIT = 5000

    def _buf(item) -> None:
        results_buffer.append(item)
        if len(results_buffer) > BUFFER_LIMIT:
            results_buffer[:len(results_buffer) - BUFFER_LIMIT] = []

    last_heartbeat = asyncio.get_event_loop().time()
    heartbeat_interval = 10.0

    async def _emit_heartbeat() -> None:
        nonlocal last_heartbeat
        now = asyncio.get_event_loop().time()
        if now - last_heartbeat >= heartbeat_interval:
            last_heartbeat = now
            await safe_queue_put(scan_id, json.dumps({
                "type": "heartbeat",
                "status": "running",
                "hosts_scanned": progress["hosts_scanned"],
                "total_hosts": progress["total_hosts"],
                "message": "Multi-host scan in progress...",
            }))

    async def on_host_port_found(target: str, port_result) -> None:
        """Callback for when a port is found on any host."""
        
        # Check for duplicate port results
        port_key = f"{target}:{port_result.port}:{port_result.protocol}"
        if port_key in progress.get("seen_ports", set()):
            logger.debug(f"Skipping duplicate host port result: {port_key}")
            return
        
        # Track seen ports to prevent duplicates
        if "seen_ports" not in progress:
            progress["seen_ports"] = set()
        progress["seen_ports"].add(port_key)
        
        evt = _build_evt(port_result)
        evt["target"] = target  # Add target to event
        _buf((target, port_result, evt))
        append_result(scan_id, evt)
        await safe_queue_put(scan_id, json.dumps(evt))

    async def _heartbeat_loop() -> None:
        while True:
            await asyncio.sleep(10.0)
            if progress["status"] in ("completed", "failed"):
                break
            try:
                await safe_queue_put(scan_id, json.dumps({
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
        await safe_queue_put(scan_id, json.dumps(summary_event))

    except asyncio.CancelledError:
        logger.warning("Multi-host scan %s cancelled for targets %s", scan_id, targets)
        progress["status"] = "cancelled"
        progress["error"] = "Scan was cancelled"
        _scan_meta[scan_id]["status"] = "cancelled"
        _scan_meta[scan_id]["error"] = "Scan was cancelled"
        _scan_meta[scan_id]["completed_at"] = datetime.now(timezone.utc).isoformat()
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
        await safe_queue_put(scan_id, "[DONE]", critical=True)
        unregister_task(scan_id)
        release_scan_slot(user_id)


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
    scan_mode: str = "port",
    ip_version: str = "auto",
) -> None:
    """Runs the actual port scan in a background task.

    Stores results in-memory always, and additionally persists to DB
    if db_scan_id is provided and DB is reachable.

    Emits heartbeat events every ~10s to keep Azure's load balancer connection alive.
    """
    progress = {"status": "running", "progress_pct": 0, "open_ports_found": 0}
    _scan_progress[scan_id] = progress
    _scan_events[scan_id] = asyncio.Queue(maxsize=QUEUE_MAXSIZE)
    _scan_meta[scan_id] = {
        "target": target,
        "port_range": port_range,
        "resolved_ip": resolved_ip,
        "scan_type": scan_mode,
        "status": "running",
        "user_id": user_id,
        "db_scan_id": db_scan_id,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "completed_at": None,
        "error": None,
    }
    _scan_results[scan_id] = []

    # Emit scan-start heartbeat so client knows scan is alive
    await safe_queue_put(scan_id, json.dumps({
        "type": "scan_start",
        "target": target,
        "port_range": port_range,
        "status": "running",
        "message": f"Scan started on {target}",
    }))

    results_buffer: list = []
    BUFFER_LIMIT = 5000

    def _buffer_append(item) -> None:
        results_buffer.append(item)
        if len(results_buffer) > BUFFER_LIMIT:
            results_buffer[:len(results_buffer) - BUFFER_LIMIT] = []

    last_heartbeat = asyncio.get_event_loop().time()
    heartbeat_interval = 10.0  # seconds — keeps Azure LB connection alive

    async def _emit_heartbeat() -> None:
        """Emit a heartbeat event if enough time has passed."""
        nonlocal last_heartbeat
        now = asyncio.get_event_loop().time()
        if now - last_heartbeat >= heartbeat_interval:
            last_heartbeat = now
            await safe_queue_put(scan_id, json.dumps({
                "type": "heartbeat",
                "status": "running",
                "open_ports_found": progress["open_ports_found"],
                "message": "Scan in progress...",
            }))

    async def on_port_found(port_result) -> None:
        logger.info(f"Port found callback: port={port_result.port}, state={port_result.state}")
        
        # Check for duplicate port results
        port_key = f"{port_result.port}:{port_result.protocol}"
        if port_key in progress.get("seen_ports", set()):
            logger.debug(f"Skipping duplicate port result: {port_key}")
            return
        
        # Track seen ports to prevent duplicates
        if "seen_ports" not in progress:
            progress["seen_ports"] = set()
        progress["seen_ports"].add(port_key)
        
        # Only increment open_ports_found for open ports
        if port_result.state == "open":
            progress["open_ports_found"] += 1
        evt = _build_evt(port_result)
        _buffer_append((port_result, evt))
        append_result(scan_id, evt)
        await safe_queue_put(scan_id, json.dumps(evt))

    async def _heartbeat_loop() -> None:
        """Background heartbeat: emits events every 10s so Azure LB never times out."""
        while True:
            await asyncio.sleep(10.0)
            if progress["status"] in ("completed", "failed"):
                break
            try:
                await safe_queue_put(scan_id, json.dumps({
                    "type": "heartbeat",
                    "status": progress["status"],
                    "progress_pct": progress["progress_pct"],
                    "open_ports_found": progress["open_ports_found"],
                    "message": f"Scan running... ({progress['open_ports_found']} open ports found)",
                }))
                # Persist heartbeat to DB for crash recovery
                if db_scan_id:
                    from cybersec.core.recovery import persist_heartbeat
                    await persist_heartbeat(db_scan_id, progress_pct=progress.get("progress_pct", 0))
            except Exception:
                break

    heartbeat_task = asyncio.create_task(_heartbeat_loop())

    try:
        # Parse rate configuration from options
        rate_preset = options.get("rate_preset", "normal") if options else "normal"
        rate_pps = options.get("rate_pps") if options else None
        
        logger.info(f"Starting scan for {target} with port_range={port_range}")
        
        scanner = AsyncPortScanner(
            timeout=3.0,
            rate_preset=rate_preset,
            rate_pps=rate_pps,
            enable_connection_pool=True
        )
        report = await scanner.scan(target, port_range, scan_mode=scan_mode, scan_callback=on_port_found, resolved_ip=resolved_ip, ip_version=ip_version)

        logger.info(f"Scan completed: {len(report.open_ports)} open ports found")
        progress["progress_pct"] = 100
        progress["status"] = "completed"

        _scan_meta[scan_id]["status"] = "completed"
        _scan_meta[scan_id]["completed_at"] = datetime.now(timezone.utc).isoformat()
        _scan_meta[scan_id]["scan_duration"] = round(report.scan_duration, 2)
        _scan_meta[scan_id]["avg_latency_ms"] = report.avg_latency_ms
        _scan_meta[scan_id]["peak_concurrency"] = report.peak_concurrency
        _scan_meta[scan_id]["total_open"] = len(report.open_ports)
        
        # ADDED: Store stress test metrics
        if report.metrics:
            _scan_meta[scan_id]["metrics"] = report.metrics

        await _persist_scan_results(db_scan_id, results_buffer, "completed")
        if db_scan_id:
            from cybersec.core.recovery import persist_status
            await persist_status(db_scan_id, "completed")

        # ADDED: Include metrics in scan complete event
        summary_event = {
            "type": "scan_complete",
            "scan_duration": round(report.scan_duration, 2),
            "avg_latency_ms": report.avg_latency_ms,
            "peak_concurrency": report.peak_concurrency,
            "total_open": len(report.open_ports),
            "metrics": report.metrics if report.metrics else None,
        }
        await safe_queue_put(scan_id, json.dumps(summary_event))

    except asyncio.CancelledError:
        logger.warning("Scan %s cancelled for target %s", scan_id, target)
        progress["status"] = "cancelled"
        progress["error"] = "Scan was cancelled"
        _scan_meta[scan_id]["status"] = "cancelled"
        _scan_meta[scan_id]["error"] = "Scan was cancelled"
        _scan_meta[scan_id]["completed_at"] = datetime.now(timezone.utc).isoformat()
        if db_scan_id:
            from cybersec.core.recovery import persist_status
            await persist_status(db_scan_id, "cancelled")
    except Exception as e:
        error_msg = f"{e.__class__.__name__}: {e}"
        progress["status"] = "failed"
        progress["error"] = error_msg
        _scan_meta[scan_id]["status"] = "failed"
        _scan_meta[scan_id]["error"] = error_msg
        logger.exception("Scan %s failed for target %s", scan_id, target)
        await _persist_scan_results(db_scan_id, results_buffer, "failed", error_msg)
        if db_scan_id:
            from cybersec.core.recovery import persist_status
            await persist_status(db_scan_id, "failed", error_message=error_msg)
    finally:
        heartbeat_task.cancel()
        try:
            await heartbeat_task
        except asyncio.CancelledError:
            pass
        await safe_queue_put(scan_id, "[DONE]", critical=True)
        unregister_task(scan_id)
        release_scan_slot(user_id)


# ─── Endpoints ───────────────────────────────────────────────────────────────

@router.post("/")
async def create_scan(
    body: ScanCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Create a new port scan and kick off background scanner.
    
    Supports CIDR ranges, IP ranges, and single targets.
    DB-OPTIONAL: If database is unavailable, scan still runs
    using in-memory storage. The response includes a `storage` field
    indicating where results are stored.
    """
    try:
        check_submit_throttle(body.target)

        # Resolve scan profile → gets ports + default settings
        from cybersec.core.profiles import resolve_profile
        profile = resolve_profile(body.port_range)
        validate_port_count(len(profile.ports))

        # Profile overrides: user-supplied values take precedence
        effective_timeout = body.timeout if body.timeout is not None else profile.timeout
        effective_rate = body.rate_preset if body.rate_preset is not None else profile.rate_preset
        effective_enrich = profile.enrich
        effective_concurrency = body.concurrency if body.concurrency is not None else profile.concurrency

        # Check if target is a CIDR range or IP range
        if '/' in body.target or '-' in body.target:
            expanded_targets = expand_target_range(body.target)
            validate_targets(expanded_targets)
            if len(expanded_targets) == 1:
                resolved_ip = expanded_targets[0]
            else:
                multi_body = MultiHostScanCreate(
                    targets=[body.target],
                    port_range=body.port_range,
                    scan_type=body.scan_type,
                    options=body.options,
                    host_concurrency_limit=body.host_concurrency_limit
                )
                return await create_multi_host_scan(multi_body, db, current_user)
        else:
            resolved_ip = await validate_target_async(body.target)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except RuntimeError as e:
        raise HTTPException(status_code=429, detail=str(e))

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
    user_id = str(current_user.id) if current_user else None

    # Try distributed execution via ARQ first (asyncio-native worker pool)
    job_id = await enqueue_scan_job(
        target=body.target,
        port_range=body.port_range,
        scan_mode=body.scan_type,
        ip_version=body.ip_version,
        user_id=user_id,
        options=body.options,
    )

    if job_id is not None:
        return {
            "id": job_id,
            "scan_id": job_id,
            "target": body.target,
            "status": "queued",
            "port_range": body.port_range,
            "storage": "arq",
            "note": "Scan submitted to ARQ worker pool",
        }

    # Fallback: Redis stream (manual worker)
    job_id = await enqueue_scan(
        target=body.target,
        port_range=body.port_range,
        scan_mode=body.scan_type,
        ip_version=body.ip_version,
        user_id=user_id,
        options=body.options,
    )

    if job_id is not None:
        return {
            "id": job_id,
            "scan_id": job_id,
            "target": body.target,
            "status": "queued",
            "port_range": body.port_range,
            "storage": "redis",
            "note": "Scan submitted to Redis stream worker pool",
        }

    # Final fallback: in-process execution (no Redis available)
    if not await acquire_scan_slot(user_id):
        raise HTTPException(
            status_code=429,
            detail=f"Scan limit reached: {MAX_CONCURRENT_SCANS_GLOBAL} global, "
                   f"{MAX_CONCURRENT_SCANS_PER_USER} per user",
        )

    task = asyncio.create_task(
        _run_scan(
            scan_id_str,
            body.target,
            body.port_range,
            resolved_ip,
            db_scan_id,
            user_id,
            body.options,
            body.scan_type,
            body.ip_version,
        )
    )
    register_task(scan_id_str, task)

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
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Create a new multi-host scan with CIDR range support.
    
    Supports multiple targets, CIDR ranges, and IP ranges.
    DB-OPTIONAL: If database is unavailable, scan still runs
    using in-memory storage.
    """
    try:
        check_submit_throttle(",".join(body.targets))

        from cybersec.core.scanner.utils import parse_ports
        parsed_ports = parse_ports(body.port_range)
        validate_port_count(len(parsed_ports))

        all_ips = []
        expanded_all = []
        for target in body.targets:
            expanded = expand_target_range(target)
            validated = validate_targets(expanded)
            all_ips.extend(validated)
            expanded_all.append(expanded)

        validate_targets(all_ips)
        body.targets = expanded_all
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except RuntimeError as e:
        raise HTTPException(status_code=429, detail=str(e))

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
    opts = dict(body.options or {})
    opts["ip_version"] = body.ip_version

    user_id = str(current_user.id) if current_user else None
    if not await acquire_scan_slot(user_id):
        raise HTTPException(
            status_code=429,
            detail=f"Scan limit reached: {MAX_CONCURRENT_SCANS_GLOBAL} global, "
                   f"{MAX_CONCURRENT_SCANS_PER_USER} per user",
        )

    task = asyncio.create_task(
        _run_multi_host_scan(
            scan_id_str,
            body.targets,
            body.port_range,
            db_scan_id,
            user_id,
            body.host_concurrency_limit,
            body.scan_type,
            opts,
        )
    )
    register_task(scan_id_str, task)

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

    Checks: Redis → in-memory → DB.
    """
    # Check ARQ-backed result (distributed worker)
    arq_result = await get_arq_status(scan_id)
    if arq_result.get("status") in ("completed", "failed"):
        return {
            "scan_id": scan_id,
            "status": arq_result["status"],
            "progress_pct": 100 if arq_result["status"] == "completed" else 0,
            "open_ports_found": len(arq_result.get("result", {}).get("open_ports", [])),
            "error": arq_result.get("error"),
            "storage": "arq",
        }

    # Check Redis-stream-backed result (manual worker)
    result = await get_job_result(scan_id)
    if result:
        return {
            "scan_id": scan_id,
            "status": result.get("status", "unknown"),
            "progress_pct": 100 if result.get("status") == "completed" else 0,
            "open_ports_found": len(result.get("open_ports", [])),
            "error": result.get("error"),
            "storage": "redis",
        }

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


@router.delete("/{scan_id}")
async def cancel_scan(scan_id: str):
    """Cancel a running scan. Cancels the background task and cleans up state."""
    from cybersec.apps.api.services.scan_state import cancel_scan as _cancel

    cancelled = await _cancel(scan_id)
    if not cancelled:
        meta = _scan_meta.get(scan_id)
        if meta and meta.get("status") in ("completed", "failed", "cancelled"):
            raise HTTPException(status_code=409, detail=f"Scan already {meta['status']}")
        raise HTTPException(status_code=404, detail="Scan not found or already completed")

    cleanup_scan(scan_id)
    return {"scan_id": scan_id, "status": "cancelled"}


@router.get("/{scan_id}/result")
async def get_scan_result(scan_id: str):
    """Get the completed scan result from Redis (distributed worker mode)."""
    result = await get_job_result(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Result not found")
    return result


@router.get("/{scan_id}/stream")
async def stream_scan_results(scan_id: str, last_id: str = "$"):
    """SSE stream delivering port results in real time as they are discovered.

    Uses Redis Streams — any API instance can serve SSE for any scan.
    Supports resumable streaming: pass ?last_id=<stream_id> to replay
    missed events after reconnection.

    Args:
        scan_id: Scan to stream.
        last_id: Redis Stream ID to resume from ("$" = newest, "0" = all).
    """
    async def event_generator():
        queue = await subscribe_events(scan_id, last_id=last_id)

        try:
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
        finally:
            await unsubscribe_events(scan_id)

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
