"""
Web App Scanner router implementation.

DB-OPTIONAL: Web app scans work even when PostgreSQL is unavailable.
Results are returned directly in the response or streamed via SSE.
"""
from fastapi import APIRouter, Depends, BackgroundTasks
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, Field
import dataclasses
import asyncio
import json
from datetime import datetime, timezone
from uuid import UUID, uuid4

from cybersec.api.deps import get_db, get_optional_user
from cybersec.database.models import Scan, ScanResult, User
from cybersec.database.session import async_session_maker
from cybersec.core.tools.webapp_scanner import WebAppScanner

router = APIRouter()

# ─── In-memory web scan stores ───────────────────────────────────────────────
_wapp_scan_meta: dict[str, dict] = {}
_wapp_scan_events: dict[str, asyncio.Queue] = {}


class WebAppScanRequest(BaseModel):
    target: str = Field(min_length=1, max_length=255)
    max_pages: int = Field(default=20, ge=1, le=100)


class WebAppScanStartRequest(BaseModel):
    target: str = Field(min_length=1, max_length=255)
    max_pages: int = Field(default=20, ge=1, le=100)


async def generate_webscan_events(
    target: str,
    max_pages: int,
    scan_id: str,
    user_id: str | None = None,
    db_scan_id: str | None = None,
):
    """Generate SSE events for a web scan, optionally persisting to DB on completion."""
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
    }
    _wapp_scan_events[scan_id] = asyncio.Queue()

    def send_event(stage: str, message: str, **extra):
        import time
        return f"data: {json.dumps({'stage': stage, 'message': message, 'timestamp': time.time(), **extra})}\n\n"

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
            headers={"User-Agent": "CyberSec-Scanner/1.0"}, follow_redirects=True
        ) as client:
            pages = await scanner.crawl(target, client)
            yield send_event('CRAWL', f'Found {len(pages)} pages', pages_found=len(pages))
            await asyncio.sleep(0)

            for check_name, check_fn in [
                ('Headers', lambda: scanner.check_missing_headers(target, client)),
                ('CORS', lambda: scanner.check_cors(target, client)),
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

                    sqli_vulns = await scanner.check_sqli(page.url, page.forms, client)
                    xss_vulns = await scanner.check_xss(page.url, page.forms, client)
                    csrf_vulns = scanner.check_csrf(page.url, page.forms)

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
        return

    seen = set()
    unique_vulns = []
    for v in all_vulns:
        key = (v.vuln_type, v.url, v.parameter)
        if key not in seen:
            seen.add(key)
            unique_vulns.append(v)

    result = scanner._build_result(target, pages, unique_vulns)
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


async def _run_web_scan_sync(
    target: str,
    max_pages: int,
    user_id: str | None = None,
) -> tuple[str, dict, str]:
    """Run web scan synchronously, return (scan_id, result_dict, storage)."""
    scanner = WebAppScanner(max_pages=max_pages)
    result = await scanner.scan(target)

    unique_vulns = result.vulnerabilities
    result_dict = dataclasses.asdict(result)

    return str(uuid4()), result_dict, "memory"


@router.post("/start-scan")
async def webapp_scan_start(
    body: WebAppScanStartRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User | None = Depends(get_optional_user)
):
    """Start a web app scan with streaming results.

    DB-OPTIONAL: If DB is unavailable, creates an in-memory scan entry.
    """
    db_scan_id: str | None = None
    storage = "memory"

    try:
        scan = Scan(
            user_id=current_user.id if current_user else None,
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

    return {
        "scan_id": scan_id,
        "target": body.target,
        "max_pages": body.max_pages,
        "storage": storage,
        "stream_url": f"/api/webapp/stream/{scan_id}",
        "note": "Results streamed via /api/webapp/stream/{scan_id}",
    }


@router.get("/stream/{scan_id}")
async def webapp_scan_stream(scan_id: str):
    """Stream web scan progress via SSE.

    If the scan was started without DB, pass target via query param ?target=...
    Otherwise the scan metadata is looked up from in-memory or DB stores.
    """
    meta = _wapp_scan_meta.get(scan_id)

    if meta:
        target = meta["target"]
        max_pages = 20
        user_id = meta.get("user_id")
        db_scan_id = meta.get("db_scan_id")
    else:
        target = None

    if not target:
        raise HTTPException(status_code=404, detail="Scan not found. Pass ?target=... if started without DB.")

    user_id = meta.get("user_id") if meta else None
    db_scan_id = meta.get("db_scan_id") if meta else None

    async def stream_response():
        try:
            async for event in generate_webscan_events(
                target, 20, scan_id, user_id, db_scan_id
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
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: User | None = Depends(get_optional_user),
):
    """Run a web app scan and return full results synchronously.

    DB-OPTIONAL: If DB is unavailable, still returns full results
    but scan_id will be a generated UUID and storage will be 'memory'.
    """
    db_scan_id: str | None = None
    storage = "memory"

    try:
        scan = Scan(
            user_id=current_user.id if current_user else None,
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

    result = await scanner.scan(body.target)
    result_dict = dataclasses.asdict(result)

    if db_scan_id:
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
async def webapp_scan_status(scan_id: str):
    """Get status of a web scan from in-memory or DB stores."""
    meta = _wapp_scan_meta.get(scan_id)
    if meta:
        vulns = meta.get("vulnerabilities", [])
        return {
            "scan_id": scan_id,
            "status": meta["status"],
            "target": meta["target"],
            "vulnerabilities_found": len(vulns),
            "storage": "memory",
        }

    try:
        async with async_session_maker() as db:
            scan = await db.get(Scan, scan_id)
            if scan:
                return {
                    "scan_id": scan_id,
                    "status": scan.status,
                    "target": scan.target,
                    "storage": "database",
                }
    except Exception:
        pass

    raise HTTPException(status_code=404, detail="Web scan not found")


from fastapi import HTTPException
