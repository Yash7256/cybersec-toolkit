"""
Scans router — full implementation.
Handles scan creation (runs AsyncPortScanner in background task),
real-time SSE streaming, status polling, OS fingerprint, and results retrieval.
"""
import asyncio
import json
import dataclasses
import logging
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cybersec.api.deps import get_db, get_optional_user
from cybersec.database.models import Scan, ScanResult, ToolResult, User
from cybersec.database.session import async_session_maker
from cybersec.core.scanner import AsyncPortScanner
from cybersec.core.utils import resolve_target

logger = logging.getLogger(__name__)

router = APIRouter()

# ─── In-memory progress store (keyed by scan_id string) ────────────────────
# Stores {scan_id: {"status", "progress_pct", "open_ports_found"}}
_scan_progress: dict[str, dict] = {}
_scan_events: dict[str, asyncio.Queue] = {}


def _safe_text(text: str | None) -> str | None:
    """Remove NULL bytes that cause PostgreSQL UTF-8 errors."""
    if text is None:
        return None
    return text.replace("\x00", "")


# ─── Schemas ────────────────────────────────────────────────────────────────

class ScanCreate(BaseModel):
    target: str = Field(min_length=1, max_length=255)
    port_range: str = Field(default="common")
    scan_type: str = Field(default="port")
    options: Optional[dict] = None

class OSFingerprintRequest(BaseModel):
    target: str = Field(min_length=1, max_length=255)


# ─── Background scan task ────────────────────────────────────────────────────

async def _run_scan(scan_id: str, target: str, port_range: str, resolved_ip: str | None = None) -> None:
    """Runs the actual port scan in a background task, updating DB as results arrive."""
    progress = {"status": "running", "progress_pct": 0, "open_ports_found": 0}
    _scan_progress[scan_id] = progress
    _scan_events[scan_id] = asyncio.Queue()

    results_buffer = []
    total_ports_hint = 100  # will be updated from scanner

    async def on_port_found(port_result) -> None:
        progress["open_ports_found"] += 1
        port_result.banner = _safe_text(port_result.banner)
        # Emit SSE event with port data
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
                    "tactics": ["Lateral Movement"] if "T1021" in technique else (["Initial Access"] if technique == "T1190" else ["Command and Control"]),
                })
        evt = {
            "port": port_result.port,
            "protocol": port_result.protocol,
            "state": port_result.state,
            "service": port_result.service.name if port_result.service else None,
            "version": port_result.service.version if port_result.service else None,
            "banner": port_result.banner,
            "risk_level": port_result.risk.risk_level if port_result.risk else "INFO",
            "risk_score": port_result.risk.risk_score if port_result.risk else 0.0,
            "cves": cves_data,
            "mitre_techniques": mitre_info,
        }
        results_buffer.append((port_result, evt))
        await _scan_events[scan_id].put(json.dumps(evt))

    try:
        scanner = AsyncPortScanner(timeout=3.0)
        report = await scanner.scan(target, port_range, scan_callback=on_port_found, resolved_ip=resolved_ip)

        progress["progress_pct"] = 100
        progress["status"] = "completed"

        # Persist results to DB
        async with async_session_maker() as db:
            scan_row = await db.get(Scan, scan_id)
            if scan_row:
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
                await db.commit()

        # Emit final adaptive scan summary
        summary_event = {
            "type": "scan_complete",
            "scan_duration": round(report.scan_duration, 2),
            "avg_latency_ms": report.avg_latency_ms,
            "peak_concurrency": report.peak_concurrency,
            "total_open": len(report.open_ports),
        }
        await _scan_events[scan_id].put(json.dumps(summary_event))

    except Exception as e:
        progress["status"] = "failed"
        progress["error"] = f"{e.__class__.__name__}: {e}"
        logger.exception("Scan %s failed for target %s", scan_id, target)
        async with async_session_maker() as db:
            scan_row = await db.get(Scan, scan_id)
            if scan_row:
                # Preserve existing options but annotate the error for visibility
                opts = scan_row.options or {}
                opts["error"] = progress["error"]
                scan_row.options = opts
                scan_row.status = "failed"
                await db.commit()
    finally:
        await _scan_events[scan_id].put("[DONE]")


# ─── Endpoints ───────────────────────────────────────────────────────────────

@router.post("/")
async def create_scan(
    body: ScanCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_user),
):
    """Create a new port scan and kick off the background scanner."""
    # Validate target early and capture the resolved IP to avoid double DNS failures
    try:
        resolved_ip = resolve_target(body.target)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    try:
        scan = Scan(
            user_id=current_user.id if current_user else None,
            target=body.target,
            scan_type=body.scan_type if body.scan_type in ("port", "web", "full") else "port",
            status="running",
            port_range=body.port_range,
            options={**(body.options or {}), "resolved_ip": resolved_ip},
            started_at=datetime.now(timezone.utc),
        )
        db.add(scan)
        await db.commit()
        await db.refresh(scan)
    except Exception as e:
        logger.warning("Create scan failed due to DB error: %s", e)
        raise HTTPException(status_code=503, detail="Database unavailable; please start Postgres and try again")

    scan_id_str = str(scan.id)
    background_tasks.add_task(_run_scan, scan_id_str, body.target, body.port_range, resolved_ip)

    return {
        "id": scan_id_str,
        "scan_id": scan_id_str,
        "target": body.target,
        "status": "running",
        "port_range": body.port_range,
    }


@router.get("/{scan_id}/status")
async def get_scan_status(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Return current status and progress for a scan."""
    progress = _scan_progress.get(scan_id)
    if progress:
        return {
            "scan_id": scan_id,
            "status": progress["status"],
            "progress_pct": progress["progress_pct"],
            "open_ports_found": progress["open_ports_found"],
            "error": progress.get("error"),
        }

    # Fallback: query DB
    try:
        scan = await db.get(Scan, scan_id)
    except Exception as e:
        logger.warning("Status lookup failed due to DB error: %s", e)
        return {
            "scan_id": scan_id,
            "status": "unknown",
            "progress_pct": 0,
            "open_ports_found": 0,
            "error": "database unavailable",
        }

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    return {
        "scan_id": scan_id,
        "status": scan.status,
        "progress_pct": 100 if scan.status == "completed" else 0,
        "open_ports_found": 0,
        "error": (scan.options or {}).get("error"),
    }


@router.get("/{scan_id}/stream")
async def stream_scan_results(scan_id: str):
    """SSE stream delivering port results in real time as they are discovered."""
    async def event_generator():
        queue = _scan_events.get(scan_id)
        if queue is None:
            # Scan already completed — replay from DB not implemented; send done
            yield "data: [DONE]\n\n"
            return

        while True:
            try:
                msg = await asyncio.wait_for(queue.get(), timeout=30.0)
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
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/{scan_id}")
async def get_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Return full scan details with all results."""
    try:
        scan = await db.get(Scan, scan_id)
    except Exception as e:
        logger.warning("Get scan failed due to DB error: %s", e)
        raise HTTPException(status_code=503, detail="Database unavailable; please start Postgres")

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    results_q = await db.execute(select(ScanResult).where(ScanResult.scan_id == scan_id))
    results = results_q.scalars().all()

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

    result_dicts = []
    for r in results:
        cves = r.cves or []
        risk = analyzer.analyze(r.port, [])
        mitre_info = []
        for technique in analyzer.MITRE_MAP.get(r.port, []):
            mitre_info.append({
                "id": technique,
                "name": mitre_names.get(technique, "Unknown Technique"),
                "tactics": ["Lateral Movement"] if "T1021" in technique else (["Initial Access"] if technique == "T1190" else ["Command and Control"]),
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
        "results": result_dicts,
    }


@router.get("/")
async def list_scans(
    limit: int = 20,
    db: AsyncSession = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_user),
):
    """List recent scans."""
    try:
        q = await db.execute(select(Scan).order_by(Scan.created_at.desc()).limit(limit))
        scans = q.scalars().all()
    except Exception as e:
        logger.warning("List scans failed due to DB error: %s", e)
        return []
    return [
        {
            "id": str(s.id),
            "target": s.target,
            "scan_type": s.scan_type,
            "status": s.status,
            "port_range": s.port_range,
            "created_at": s.created_at.isoformat() if s.created_at else None,
        }
        for s in scans
    ]


# ─── OS Fingerprint ──────────────────────────────────────────────────────────

@router.post("/os-fingerprint")
async def os_fingerprint(
    body: OSFingerprintRequest,
    db: AsyncSession = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_user),
):
    """Run OS fingerprinting by scanning key ports and analyzing banners."""
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

    tool_result = ToolResult(
        user_id=current_user.id if current_user else None,
        tool_name="os_fingerprint",
        target=body.target,
        result_data={
            "os_name": fp.os_name,
            "confidence": fp.confidence,
            "method": fp.method,
            "open_ports": [r.port for r in report.open_ports],
            "scan_duration": report.scan_duration,
        },
    )
    db.add(tool_result)
    await db.commit()
    await db.refresh(tool_result)

    return {
        "target": body.target,
        "ip": report.ip,
        "os_name": fp.os_name,
        "confidence": fp.confidence,
        "confidence_pct": round(fp.confidence * 100, 1),
        "method": fp.method,
        "open_ports_scanned": [r.port for r in report.open_ports],
        "tool_result_id": str(tool_result.id),
    }
