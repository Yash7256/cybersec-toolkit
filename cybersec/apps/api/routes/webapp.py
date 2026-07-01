"""
Web App Scanner router implementation.

DB-OPTIONAL: Web app scans work even when PostgreSQL is unavailable.
Results are returned directly in the response or streamed via SSE.
Azure-compatible: sends heartbeat events every 10s to prevent LB timeout.
"""
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, Field
import dataclasses
import asyncio
import json
import time
from datetime import datetime, timezone
from uuid import uuid4

from cybersec.apps.api.deps import get_db, get_current_user
from cybersec.apps.api.tier import check_and_increment_usage
from cybersec.config.settings import settings
from cybersec.database.models import Scan, ScanResult, User
from cybersec.database.session import async_session_maker
from cybersec.core.tools.webapp_scanner import WebAppScanner

router = APIRouter()

# ─── In-memory web scan stores ───────────────────────────────────────────────
# Values include a `_ts` key (monotonic seconds) for TTL eviction.
_wapp_scan_meta: dict[str, dict] = {}
_wapp_scan_events: dict[str, asyncio.Queue] = {}
_cleanup_task: asyncio.Task | None = None


def _register_cleanup(loop: asyncio.AbstractEventLoop | None = None) -> None:
    """Start the background TTL cleanup task once per process."""
    global _cleanup_task
    if _cleanup_task is not None and not _cleanup_task.done():
        return
    try:
        _cleanup_task = asyncio.get_event_loop().create_task(_ttl_cleanup_loop())
    except RuntimeError:
        pass  # no running loop yet; will be started lazily on first request


async def _ttl_cleanup_loop() -> None:
    """Periodically evict scan state older than WEBAPP_SCAN_STATE_TTL_SECONDS."""
    while True:
        await asyncio.sleep(min(300, settings.WEBAPP_SCAN_STATE_TTL_SECONDS // 2))
        cutoff = time.monotonic() - settings.WEBAPP_SCAN_STATE_TTL_SECONDS
        expired = [sid for sid, meta in list(_wapp_scan_meta.items()) if meta.get("_ts", 0) < cutoff]
        for sid in expired:
            _wapp_scan_meta.pop(sid, None)
            _wapp_scan_events.pop(sid, None)


# ─── Request models ───────────────────────────────────────────────────────────

class WebAppScanRequest(BaseModel):
    target: str = Field(min_length=1, max_length=255)
    max_pages: int = Field(default=20, ge=1, le=100)
    confirm_authorized: bool  # required — no default


class WebAppScanStartRequest(BaseModel):
    target: str = Field(min_length=1, max_length=255)
    max_pages: int = Field(default=20, ge=1, le=100)
    confirm_authorized: bool  # required — no default


_AUTH_GATE_MSG = (
    "You must confirm you are authorized to actively test this target "
    "before running injection payloads against it."
)


async def generate_webscan_events(
    target: str,
    max_pages: int,
    scan_id: str,
    allow_private: bool = False,
    user_id: str | None = None,
    db_scan_id: str | None = None,
):
    """Generate SSE events for a web scan with heartbeat support for Azure.

    Sends a heartbeat event every 10 seconds to prevent Azure's load balancer
    from closing the SSE connection during long scans.
    """
    import httpx
    scanner = WebAppScanner(max_pages=max_pages)

    _wapp_scan_meta[scan_id] = {
        "target": target,
        "status": "running",
        "user_id": user_id,
        "db_scan_id": db_scan_id,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "completed_at": None,
        "error": None,
        "vulnerabilities": [],
        "_ts": time.monotonic(),
    }
    _wapp_scan_events[scan_id] = asyncio.Queue(maxsize=1000)

    async def _heartbeat_loop() -> None:
        """Send heartbeat every 10s to keep Azure LB connection alive."""
        while True:
            await asyncio.sleep(10.0)
            meta = _wapp_scan_meta.get(scan_id)
            if meta is None or meta["status"] in ("completed", "failed"):
                break
            try:
                await _wapp_scan_events[scan_id].put(json.dumps({
                    "stage": "heartbeat",
                    "message": "Scan in progress...",
                    "timestamp": asyncio.get_event_loop().time(),
                }))
            except Exception:
                break

    heartbeat_task = asyncio.create_task(_heartbeat_loop())
    _register_cleanup()

    def send_event(stage: str, message: str, **extra):
        return f"data: {json.dumps({'stage': stage, 'message': message, 'timestamp': asyncio.get_event_loop().time(), **extra})}\n\n"

    await asyncio.sleep(0)
    yield send_event('INIT', f'Starting web scan on {target}')
    await asyncio.sleep(0)

    yield send_event('CONFIG', f'Max pages: {max_pages}')
    await asyncio.sleep(0)

    yield send_event('CRAWL', 'Discovering pages...')
    await asyncio.sleep(0)

    all_vulns = []
    pages = []

    try:
        async with httpx.AsyncClient(
            timeout=scanner.timeout, verify=False,
            headers={"User-Agent": "CyberSec-Scanner/1.0"}, follow_redirects=False
        ) as client:
            pages = await scanner.crawl(target, client, allow_private=allow_private)
            yield send_event('CRAWL', f'Found {len(pages)} pages', pages_found=len(pages))
            await asyncio.sleep(0)

            for check_name, check_fn in [
                ('Headers', lambda: scanner.check_headers(target, client, allow_private=allow_private)),
                ('CORS', lambda: scanner.check_cors(target, client, allow_private=allow_private)),
                ('Files', lambda: scanner.check_exposed_files(target, client)),
            ]:
                yield send_event('CHECK', f'Checking {check_name.lower()}...')
                await asyncio.sleep(0)
                vulns = await check_fn()
                all_vulns.extend(vulns)
                yield send_event('CHECK', f'{check_name} check complete', vuln_count=len(vulns))
                await asyncio.sleep(0)

            for i, page in enumerate(pages):
                yield send_event('SCAN', f'Scanning page {i+1}/{len(pages)}: {page.url[:50]}',
                                 page_num=i+1, total_pages=len(pages), running=True)
                await asyncio.sleep(0)

                if page.forms:
                    yield send_event('CHECK', f'Checking {len(page.forms)} form(s) on {page.url[:50]}...',
                                     form_count=len(page.forms))
                    await asyncio.sleep(0)

                    sqli_vulns = await scanner.check_sqli(page.url, page.forms, client, allow_private=allow_private)
                    xss_vulns = await scanner.check_xss(page.url, page.forms, client, allow_private=allow_private)
                    csrf_vulns = await scanner.check_csrf(page.url, page.forms)

                    all_vulns.extend(sqli_vulns)
                    all_vulns.extend(xss_vulns)
                    all_vulns.extend(csrf_vulns)

                    yield send_event('CHECK', f'SQLi/XSS/CSRF checks done on page {i+1}',
                                     vuln_count=len(sqli_vulns) + len(xss_vulns) + len(csrf_vulns))
                    await asyncio.sleep(0)

                    if sqli_vulns or xss_vulns or csrf_vulns:
                        yield send_event('VULN',
                                         f'Found {len(sqli_vulns)} SQLi, {len(xss_vulns)} XSS, {len(csrf_vulns)} CSRF')
                        await asyncio.sleep(0)
                await asyncio.sleep(0.02)
    except Exception as e:
        yield send_event('ERROR', f'Scan error: {str(e)}')
        _wapp_scan_meta[scan_id]["status"] = "failed"
        _wapp_scan_meta[scan_id]["error"] = str(e)
    finally:
        heartbeat_task.cancel()
        try:
            await heartbeat_task
        except asyncio.CancelledError:
            pass

    seen = set()
    unique_vulns = []
    for v in all_vulns:
        key = (v.vuln_type, v.url, v.parameter)
        if key not in seen:
            seen.add(key)
            unique_vulns.append(v)

    result = scanner._build_result(target=target, pages=pages, vulns=unique_vulns)
    result_dict = dataclasses.asdict(result)

    _wapp_scan_meta[scan_id]["status"] = "completed"
    _wapp_scan_meta[scan_id]["completed_at"] = datetime.now(timezone.utc).isoformat()
    _wapp_scan_meta[scan_id]["vulnerabilities"] = unique_vulns

    await _persist_web_scan(db_scan_id, unique_vulns)

    yield send_event('DONE', f'Scan complete. Found {len(unique_vulns)} vulnerabilities.',
                     result=result_dict)
    await asyncio.sleep(0)


async def _persist_web_scan(db_scan_id: str | None, vulns: list) -> None:
    """Persist web scan results to DB if available; silently skip on failure."""
    if not db_scan_id:
        return
    try:
        async with async_session_maker() as db:
            scan = await db.get(Scan, db_scan_id)
            if scan:
                for vuln in vulns:
                    db.add(ScanResult(
                        scan_id=scan.id,
                        port=None,
                        protocol="http",
                        state="open",
                        service=vuln.vuln_type,
                        version=None,
                        banner=vuln.evidence,
                        cves=[],
                    ))
                scan.status = "completed"
                scan.completed_at = datetime.now(timezone.utc)
                await db.commit()
    except Exception as e:
        import logging
        logging.getLogger(__name__).warning("Failed to persist web scan to DB (scan=%s): %s", db_scan_id, e)


@router.post("/start-scan")
async def webapp_scan_start(
    body: WebAppScanStartRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Start a web app scan with streaming results.

    DB-OPTIONAL: If DB is unavailable, creates an in-memory scan entry.
    """
    if not body.confirm_authorized:
        raise HTTPException(status_code=400, detail=_AUTH_GATE_MSG)

    await check_and_increment_usage(current_user, db, tool_name="webapp")

    allow_private = bool(settings.ALLOW_PRIVATE_TARGET_SCANS)

    db_scan_id: str | None = None
    storage = "memory"

    try:
        scan = Scan(
            user_id=current_user.id,
            target=body.target,
            scan_type="web",
            status="running",
            started_at=datetime.now(timezone.utc),
        )
        db.add(scan)
        await db.commit()
        await db.refresh(scan)
        db_scan_id = str(scan.id)
        storage = "database"
    except Exception as e:
        import logging
        logging.getLogger(__name__).warning("Web scan start DB unavailable (target=%s): %s", body.target, e)

    scan_id = db_scan_id if db_scan_id else str(uuid4())

    _wapp_scan_meta[scan_id] = {
        "target": body.target,
        "status": "pending",
        "allow_private": allow_private,
        "max_pages": body.max_pages,
        "user_id": current_user.id,
        "db_scan_id": db_scan_id,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "completed_at": None,
        "error": None,
        "vulnerabilities": [],
        "_ts": time.monotonic(),
    }
    _register_cleanup()

    return {
        "scan_id": scan_id,
        "target": body.target,
        "max_pages": body.max_pages,
        "storage": storage,
        "stream_url": f"/api/webapp/stream/{scan_id}",
        "note": "Results streamed via /api/webapp/stream/{scan_id}",
    }


@router.get("/stream/{scan_id}")
async def webapp_scan_stream(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Stream web scan progress via SSE.

    Requires authentication. Only the user who started the scan can stream it.
    Azure-compatible: heartbeat every 10s, keepalive every 55s.
    """
    meta = _wapp_scan_meta.get(scan_id)

    if not meta:
        raise HTTPException(status_code=404, detail="Scan not found. Start a scan first via /api/webapp/start-scan or /api/webapp/scan.")

    # Ownership check — only the user who created the scan can stream it
    if meta.get("user_id") and str(meta["user_id"]) != str(current_user.id):
        raise HTTPException(status_code=403, detail="Access denied")

    target = meta["target"]
    user_id = meta.get("user_id")
    db_scan_id = meta.get("db_scan_id")
    allow_private = meta.get("allow_private", False)
    max_pages = meta.get("max_pages", 20)

    async def stream_response():
        try:
            async for event in generate_webscan_events(
                target, max_pages, scan_id, allow_private, user_id, db_scan_id
            ):
                yield event
        except Exception as e:
            import logging
            logging.getLogger(__name__).warning("Web scan stream error (scan_id=%s): %s", scan_id, e)

    return StreamingResponse(
        stream_response(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
            "Transfer-Encoding": "chunked",
        },
    )


@router.post("/scan")
async def webapp_scan(
    body: WebAppScanRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Run a web app scan and return full results synchronously.

    DB-OPTIONAL: If DB is unavailable, still returns full results
    but scan_id will be a generated UUID and storage will be 'memory'.
    """
    if not body.confirm_authorized:
        raise HTTPException(status_code=400, detail=_AUTH_GATE_MSG)

    await check_and_increment_usage(current_user, db, tool_name="webapp")

    allow_private = bool(settings.ALLOW_PRIVATE_TARGET_SCANS)

    db_scan_id: str | None = None
    storage = "memory"
    scan = None

    try:
        scan = Scan(
            user_id=current_user.id,
            target=body.target,
            scan_type="web",
            status="running",
            started_at=datetime.now(timezone.utc),
        )
        db.add(scan)
        await db.commit()
        await db.refresh(scan)
        db_scan_id = str(scan.id)
        storage = "database"
    except Exception as e:
        import logging
        logging.getLogger(__name__).warning("Web scan DB unavailable (target=%s): %s", body.target, e)

    scan_id = db_scan_id if db_scan_id else str(uuid4())
    scanner = WebAppScanner(max_pages=body.max_pages)

    result = await scanner.scan(body.target, allow_private=allow_private)
    result_dict = dataclasses.asdict(result)

    if db_scan_id and scan is not None:
        try:
            for vuln in result.vulnerabilities:
                db.add(ScanResult(
                    scan_id=scan.id,
                    port=None,
                    protocol="http",
                    state="open",
                    service=vuln.vuln_type,
                    version=None,
                    banner=vuln.evidence,
                    cves=[],
                ))
            scan.status = "completed"
            scan.completed_at = datetime.now(timezone.utc)
            await db.commit()
        except Exception as e:
            import logging
            logging.getLogger(__name__).warning("Failed to persist web scan results (scan=%s): %s", db_scan_id, e)

    return {
        "scan_id": scan_id,
        "target": body.target,
        "storage": storage,
        "result": result_dict,
    }


@router.get("/{scan_id}/status")
async def webapp_scan_status(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get status of a web scan. Requires authentication and ownership."""
    meta = _wapp_scan_meta.get(scan_id)
    if meta:
        # Ownership check
        if meta.get("user_id") and str(meta["user_id"]) != str(current_user.id):
            raise HTTPException(status_code=403, detail="Access denied")
        vulns = meta.get("vulnerabilities", [])
        return {
            "scan_id": scan_id,
            "status": meta["status"],
            "target": meta["target"],
            "vulnerabilities_found": len(vulns),
            "storage": "memory",
        }

    try:
        async with async_session_maker() as session:
            scan = await session.get(Scan, scan_id)
            if scan:
                # Ownership check from DB
                if scan.user_id and str(scan.user_id) != str(current_user.id):
                    raise HTTPException(status_code=403, detail="Access denied")
                return {
                    "scan_id": scan_id,
                    "status": scan.status,
                    "target": scan.target,
                    "storage": "database",
                }
    except HTTPException:
        raise
    except Exception:
        pass

    raise HTTPException(status_code=404, detail="Web scan not found")
