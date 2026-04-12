"""
Web App Scanner router implementation.
"""
from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, Field
import dataclasses
import asyncio
import json
import sys
from datetime import datetime
from uuid import UUID

from cybersec.api.deps import get_db, get_optional_user
from cybersec.database.models import Scan, ScanResult, User
from cybersec.core.tools.webapp_scanner import WebAppScanner

router = APIRouter()

class WebAppScanRequest(BaseModel):
    target: str = Field(min_length=1, max_length=255)
    max_pages: int = Field(default=20, ge=1, le=100)

class WebAppScanStartRequest(BaseModel):
    target: str = Field(min_length=1, max_length=255)
    max_pages: int = Field(default=20, ge=1, le=100)

async def generate_webscan_events(target: str, max_pages: int, db: AsyncSession, scan_id: UUID):
    import httpx
    scanner = WebAppScanner(max_pages=max_pages)
    
    def send_event(stage: str, message: str, **extra):
        import time
        return f"data: {json.dumps({'stage': stage, 'message': message, 'timestamp': time.time(), **extra})}\n\n"
    
    async def yield_and_flush(content):
        await asyncio.sleep(0)
        sys.stdout.flush()
        return content
    
    yield send_event('INIT', f'Starting web scan on {target}')
    await asyncio.sleep(0)
    
    yield send_event('CONFIG', f'Max pages: {max_pages}')
    await asyncio.sleep(0)
    
    yield send_event('CRAWL', 'Discovering pages...')
    await asyncio.sleep(0)
    
    all_vulns = []
    
    try:
        async with httpx.AsyncClient(timeout=scanner.timeout, verify=False, headers={"User-Agent": "CyberSec-Scanner/1.0"}, follow_redirects=True) as client:
            pages = await scanner.crawl(target, client)
            yield send_event('CRAWL', f'Found {len(pages)} pages', pages_found=len(pages))
            await asyncio.sleep(0)
            
            yield send_event('CHECK', 'Checking security headers...')
            await asyncio.sleep(0)
            headers_vulns = await scanner.check_missing_headers(target, client)
            all_vulns.extend(headers_vulns)
            yield send_event('CHECK', f'Headers check complete', vuln_count=len(headers_vulns))
            await asyncio.sleep(0)
            
            yield send_event('CHECK', 'Checking CORS configuration...')
            await asyncio.sleep(0)
            cors_vulns = await scanner.check_cors(target, client)
            all_vulns.extend(cors_vulns)
            yield send_event('CHECK', f'CORS check complete', vuln_count=len(cors_vulns))
            await asyncio.sleep(0)
            
            yield send_event('CHECK', 'Checking exposed files...')
            await asyncio.sleep(0)
            exposed_vulns = await scanner.check_exposed_files(target, client)
            all_vulns.extend(exposed_vulns)
            yield send_event('CHECK', f'File check complete', vuln_count=len(exposed_vulns))
            await asyncio.sleep(0)
            
            for i, page in enumerate(pages):
                yield send_event('SCAN', f'Scanning page {i+1}/{len(pages)}: {page.url}', page_num=i+1, total_pages=len(pages), running=True)
                await asyncio.sleep(0)
                
                if page.forms:
                    yield send_event('CHECK', f'Checking {len(page.forms)} form(s) on {page.url[:50]}...', form_count=len(page.forms))
                    await asyncio.sleep(0)
                    
                    sqli_vulns = await scanner.check_sqli(page.url, page.forms, client)
                    yield send_event('CHECK', f'SQLi check done on page {i+1}', vuln_count=len(sqli_vulns))
                    await asyncio.sleep(0)
                    
                    xss_vulns = await scanner.check_xss(page.url, page.forms, client)
                    yield send_event('CHECK', f'XSS check done on page {i+1}', vuln_count=len(xss_vulns))
                    await asyncio.sleep(0)
                    
                    csrf_vulns = await scanner.check_csrf(page.url, page.forms)
                    all_vulns.extend(sqli_vulns)
                    all_vulns.extend(xss_vulns)
                    all_vulns.extend(csrf_vulns)
                    if sqli_vulns or xss_vulns or csrf_vulns:
                        yield send_event('VULN', f'Found {len(sqli_vulns)} SQLi, {len(xss_vulns)} XSS, {len(csrf_vulns)} CSRF on this page')
                        await asyncio.sleep(0)
                await asyncio.sleep(0.02)
    except Exception as e:
        yield send_event('ERROR', f'Scan error: {str(e)}')
        return
    
    seen = set()
    unique_vulns = []
    for v in all_vulns:
        key = (v.vuln_type, v.url, v.parameter)
        if key not in seen:
            seen.add(key)
            unique_vulns.append(v)
    
    result = scanner._build_result(target, pages if 'pages' in dir() else [], unique_vulns)
    result_dict = dataclasses.asdict(result)
    
    yield send_event('DONE', f'Scan complete. Found {len(unique_vulns)} vulnerabilities.', result=result_dict)
    await asyncio.sleep(0)

@router.post("/start-scan")
async def webapp_scan_start(
    body: WebAppScanStartRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User | None = Depends(get_optional_user)
):
    scan = Scan(
        user_id=current_user.id if current_user else None,
        target=body.target,
        scan_type="web",
        status="running",
        started_at=datetime.utcnow()
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)
    
    return {"scan_id": str(scan.id), "target": body.target, "max_pages": body.max_pages}

@router.get("/stream/{scan_id}")
async def webapp_scan_stream(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    try:
        scan = await db.get(Scan, scan_id)
    except:
        scan = None
    
    target = scan.target if scan else "unknown"
    max_pages = 20
    
    async def stream_response():
        try:
            async for event in generate_webscan_events(target, max_pages, db, scan_id):
                yield event
            
            if scan:
                scan.status = "completed"
                scan.completed_at = datetime.utcnow()
                await db.commit()
        except Exception as e:
            yield f"data: {json.dumps({'stage': 'ERROR', 'message': str(e)})}\n\n"
    
    return StreamingResponse(
        stream_response(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
            "Transfer-Encoding": "chunked"
        }
    )

@router.post("/scan")
async def webapp_scan(
    body: WebAppScanRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User | None = Depends(get_optional_user)
):
    scan = Scan(
        user_id=current_user.id if current_user else None,
        target=body.target,
        scan_type="web",
        status="running",
        started_at=datetime.utcnow()
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    scanner = WebAppScanner(max_pages=body.max_pages)
    result = await scanner.scan(body.target)
    
    result_dict = dataclasses.asdict(result)
    
    for vuln in result.vulnerabilities:
        scan_result = ScanResult(
            scan_id=scan.id,
            port=None,
            protocol="http",
            state="open",
            service=vuln.vuln_type,
            version=None,
            banner=vuln.evidence,
            cves=[]
        )
        db.add(scan_result)

    scan.status = "completed"
    scan.completed_at = datetime.utcnow()
    
    await db.commit()
    
    return {
        "scan_id": str(scan.id),
        "target": body.target,
        "result": result_dict
    }
