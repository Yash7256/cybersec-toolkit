"""
Tools router implementation.
"""
import asyncio
import logging
from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from cybersec.apps.api.deps import get_db, get_optional_user
from cybersec.database.models import User, ToolResult
import dataclasses
import json

from cybersec.apps.api.schemas.tool import (
    DnsRequest, WhoisRequest, PingRequest, TracerouteRequest,
    SslRequest, HttpHeadersRequest, SubdomainRequest, GeoipRequest,
    OsFingerprintRequest, PortScanRequest, PortScanOut, OpenPortOut, ToolResultOut
)
from cybersec.config.settings import settings
from cybersec.core.tools.port_scanner import PortScanResult

from cybersec.core.tools.dns import dns_lookup
from cybersec.core.tools.whois import whois_lookup
from cybersec.core.tools.ping import ping_host
from cybersec.core.tools.traceroute import traceroute
from cybersec.core.tools.ssl import ssl_audit
from cybersec.core.tools.http_headers import check_http_headers
from cybersec.core.tools.subdomain import find_subdomains, stream_subdomain_events
from cybersec.core.tools.geoip import geoip_lookup
from cybersec.core.tools.os_fingerprint import os_fingerprint, stream_os_fingerprint_events
from cybersec.core.tools.port_scanner import scan_ports, scan_port_range, stream_port_scan_events


def _port_scan_to_dict(result: PortScanResult) -> dict:
    """Serialize scan result with banner fields for the frontend."""
    return PortScanOut(
        target=result.target,
        total_scanned=result.total_scanned,
        open_ports_count=result.open_ports_count,
        open_ports=[
            OpenPortOut(
                port_number=p.port_number,
                service=p.service,
                status=p.status,
                version=p.version,
                raw_banner=p.raw_banner,
                welcome_message=p.welcome_message,
                server_response=p.server_response,
                risk_level=p.risk_level,
                risk_reason=p.risk_reason,
                service_description=p.service_description,
                service_security_concern=p.service_security_concern,
                technologies=p.technologies,
                screenshot=p.screenshot,
                screenshot_url=p.screenshot_url,
                recommendation=p.recommendation,
                recommendation_reason=p.recommendation_reason,
                recommendation_priority=p.recommendation_priority,
                mitre_attack=p.mitre_attack,
                potential_threat=p.potential_threat,
                exploit_availability=p.exploit_availability,
                misconfigurations=p.misconfigurations,
                exposure_severity=p.exposure_severity,
                cve_result=dataclasses.asdict(p.cve_result) if p.cve_result else None,
                cve_count=p.cve_count,
                cve_critical_count=p.cve_critical_count,
                cve_high_count=p.cve_high_count,
                cve_medium_count=p.cve_medium_count,
                cve_low_count=p.cve_low_count,
                max_cvss_score=p.max_cvss_score,
                max_cvss_severity=p.max_cvss_severity,
                max_cvss_cve=p.max_cvss_cve,
                fingerprint=p.fingerprint,
            )
            for p in result.open_ports
        ],
        detected_technologies=result.detected_technologies,
        scan_duration_seconds=result.scan_duration_seconds,
        packets_sent=result.packets_sent,
        avg_latency_ms=result.avg_latency_ms,
        security_score=result.security_score,
        security_score_factors=result.security_score_factors,
        attack_surface=result.attack_surface,
        threat_intelligence=result.threat_intelligence,
        misconfiguration_summary=result.misconfiguration_summary,
        exposure_summary=result.exposure_summary,
        attack_paths=result.attack_paths,
        attack_simulations=result.attack_simulations,
        recommendations_error=result.recommendations_error,
        error=result.error,
    ).model_dump()

router = APIRouter()
logger = logging.getLogger(__name__)


async def _save_tool_result(db: AsyncSession, current_user: User | None, tool_name: str, target: str, result_dict: dict) -> str | None:
    """Persist tool result if DB is available; return ID or None on failure."""
    try:
        row = ToolResult(
            user_id=current_user.id if current_user else None,
            tool_name=tool_name,
            target=target,
            result_data=result_dict
        )
        db.add(row)
        await db.commit()
        await db.refresh(row)
        return str(row.id)
    except Exception as e:
        logger.warning("Tool result not saved (tool=%s target=%s): %s", tool_name, target, e)
        try:
            await db.rollback()
        except Exception:
            pass
        return None

@router.post("/dns")
async def run_dns(
    body: DnsRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User | None = Depends(get_optional_user)
):
    result = await dns_lookup(body.target, body.record_type)
    result_dict = dataclasses.asdict(result)
    tool_result_id = await _save_tool_result(db, current_user, "dns", body.target, result_dict)
    return {"tool_result_id": tool_result_id, "data": result_dict}

@router.post("/whois")
async def run_whois(
    body: WhoisRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User | None = Depends(get_optional_user)
):
    result = await whois_lookup(body.target)
    result_dict = dataclasses.asdict(result)
    tool_result_id = await _save_tool_result(db, current_user, "whois", body.target, result_dict)
    return {"tool_result_id": tool_result_id, "data": result_dict}


@router.post("/whois/stream")
async def stream_whois(
    body: WhoisRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User | None = Depends(get_optional_user)
):
    async def stream_response():
        queue: asyncio.Queue[str | None] = asyncio.Queue()

        async def on_stage(stage: str, message: str) -> None:
            await queue.put(
                f"data: {json.dumps({'type': 'stage', 'stage': stage, 'message': message})}\n\n"
            )

        try:
            yield f"data: {json.dumps({'type': 'init', 'data': {'target': body.target, 'domain': body.target, 'scanning': True, 'scan_stage': 'init', 'scan_message': 'Starting WHOIS lookup'}})}\n\n"

            lookup_task = asyncio.create_task(whois_lookup(body.target, on_stage=on_stage))

            while not lookup_task.done():
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=0.1)
                    yield event
                except asyncio.TimeoutError:
                    continue

            # Drain any remaining stage events enqueued before the task finished
            while not queue.empty():
                yield queue.get_nowait()

            result = await lookup_task
            result_dict = dataclasses.asdict(result)
            tool_result_id = await _save_tool_result(db, current_user, "whois", body.target, result_dict)
            yield f"data: {json.dumps({'type': 'done', 'data': result_dict, 'tool_result_id': tool_result_id})}\n\n"
        except Exception as e:
            logger.exception("WHOIS stream failed for %s", body.target)
            yield f"data: {json.dumps({'type': 'error', 'error': str(e)})}\n\n"

    return StreamingResponse(
        stream_response(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


@router.get("/whois")
async def run_whois_get(
    target: str = Query(...),
    db: AsyncSession = Depends(get_db),
    current_user: User | None = Depends(get_optional_user)
):
    result = await whois_lookup(target)
    result_dict = dataclasses.asdict(result)
    tool_result_id = await _save_tool_result(db, current_user, "whois", target, result_dict)
    return {"tool_result_id": tool_result_id, "data": result_dict}

@router.post("/ping")
async def run_ping(
    body: PingRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User | None = Depends(get_optional_user)
):
    result = await ping_host(body.target, body.count)
    result_dict = dataclasses.asdict(result)
    tool_result_id = await _save_tool_result(db, current_user, "ping", body.target, result_dict)
    return {"tool_result_id": tool_result_id, "data": result_dict}

@router.post("/traceroute")
async def run_traceroute(
    body: TracerouteRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User | None = Depends(get_optional_user)
):
    result = await traceroute(body.target, body.max_hops)
    result_dict = dataclasses.asdict(result)
    tool_result_id = await _save_tool_result(db, current_user, "traceroute", body.target, result_dict)
    return {"tool_result_id": tool_result_id, "data": result_dict}

@router.post("/ssl")
async def run_ssl(
    body: SslRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User | None = Depends(get_optional_user)
):
    result = await ssl_audit(body.host, body.port)
    result_dict = dataclasses.asdict(result)
    
    cert_data = result_dict.get("cert")
    if cert_data:
        result_dict["certificate"] = {
            "valid_from": cert_data.get("valid_from"),
            "valid_to": cert_data.get("valid_until"),
            "days_remaining": cert_data.get("days_remaining"),
            "issuer": cert_data.get("issuer"),
            "subject": cert_data.get("subject"),
            "san": cert_data.get("san"),
            "is_expired": cert_data.get("is_expired"),
        }
        del result_dict["cert"]
    
    result_dict["valid"] = result_dict.get("cert_is_expired") is not True
    
    result_dict["tls_version"] = result_dict.get("tls_version")
    result_dict["cipher_suite"] = result_dict.get("cipher_suite")
    
    logger.info(f"=== SSL RAW RESPONSE for {body.host} ===")
    logger.info(result_dict)
    logger.info("==========================================")
    
    tool_result_id = await _save_tool_result(db, current_user, "ssl", body.host, result_dict)
    return {"tool_result_id": tool_result_id, "data": result_dict}

@router.post("/http_headers")
async def run_http_headers(
    body: HttpHeadersRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User | None = Depends(get_optional_user)
):
    result = await check_http_headers(body.target, body.path)
    result_dict = dataclasses.asdict(result)
    tool_result_id = await _save_tool_result(db, current_user, "http_headers", body.target, result_dict)
    return {"tool_result_id": tool_result_id, "data": result_dict}

@router.post("/subdomain")
async def run_subdomain(
    body: SubdomainRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User | None = Depends(get_optional_user)
):
    result = await find_subdomains(body.domain, body.wordlist, body.strictness)
    result_dict = dataclasses.asdict(result)
    tool_result_id = await _save_tool_result(db, current_user, "subdomain", body.domain, result_dict)
    return {"tool_result_id": tool_result_id, "data": result_dict}


@router.post("/subdomain/stream")
async def stream_subdomain(
    body: SubdomainRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User | None = Depends(get_optional_user)
):
    async def stream_response():
        try:
            async for event in stream_subdomain_events(body.domain, body.wordlist, body.strictness):
                if event.get("type") == "done":
                    tool_result_id = await _save_tool_result(db, current_user, "subdomain", body.domain, event["data"])
                    event["tool_result_id"] = tool_result_id
                yield f"data: {json.dumps(event)}\n\n"
        except Exception as e:
            logger.exception("Subdomain stream failed for %s", body.domain)
            yield f"data: {json.dumps({'type': 'error', 'error': str(e)})}\n\n"

    return StreamingResponse(
        stream_response(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )

@router.post("/geoip")
async def run_geoip(
    body: GeoipRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User | None = Depends(get_optional_user)
):
    result = await geoip_lookup(body.target)
    result_dict = dataclasses.asdict(result)
    tool_result_id = await _save_tool_result(db, current_user, "geoip", body.target, result_dict)
    return {"tool_result_id": tool_result_id, "data": result_dict}


@router.post("/geoip/stream")
async def stream_geoip(
    body: GeoipRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User | None = Depends(get_optional_user)
):
    async def stream_response():
        try:
            yield f"data: {json.dumps({'type': 'init', 'data': {'target': body.target, 'ip': None, 'resolved_ips': [], 'ip_results': [], 'provider': 'ipwhois', 'cached': False, 'scanning': True, 'scan_stage': 'init', 'scan_message': 'Starting GeoIP lookup'}})}\n\n"
            yield f"data: {json.dumps({'type': 'stage', 'stage': 'resolve', 'message': 'Resolving target address'})}\n\n"
            yield f"data: {json.dumps({'type': 'stage', 'stage': 'provider', 'message': 'Querying GeoIP provider and RDAP registry'})}\n\n"
            result = await geoip_lookup(body.target)
            result_dict = dataclasses.asdict(result)
            tool_result_id = await _save_tool_result(db, current_user, "geoip", body.target, result_dict)
            yield f"data: {json.dumps({'type': 'done', 'data': result_dict, 'tool_result_id': tool_result_id})}\n\n"
        except Exception as e:
            logger.exception("GeoIP stream failed for %s", body.target)
            yield f"data: {json.dumps({'type': 'error', 'error': str(e)})}\n\n"

    return StreamingResponse(
        stream_response(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


@router.get("/geoip")
@router.get("/geo")
async def run_geoip_legacy_get(
    target: str = Query(...),
    db: AsyncSession = Depends(get_db),
    current_user: User | None = Depends(get_optional_user)
):
    result = await geoip_lookup(target)
    result_dict = dataclasses.asdict(result)
    tool_result_id = await _save_tool_result(db, current_user, "geoip", target, result_dict)
    return {"tool_result_id": tool_result_id, "data": result_dict}

@router.post("/os-fingerprint")
@router.post("/os_fingerprint")
async def run_os_fingerprint(
    body: OsFingerprintRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User | None = Depends(get_optional_user)
):
    allow_private = bool(current_user and settings.ALLOW_PRIVATE_TARGET_SCANS)
    result = await os_fingerprint(body.target, timeout=body.timeout, allow_private=allow_private, db_session=db)
    result_dict = dataclasses.asdict(result)
    tool_result_id = await _save_tool_result(db, current_user, "os_fingerprint", body.target, result_dict)
    return {"tool_result_id": tool_result_id, "data": result_dict}


@router.post("/os-fingerprint/stream")
@router.post("/os_fingerprint/stream")
async def stream_os_fingerprint(
    body: OsFingerprintRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User | None = Depends(get_optional_user)
):
    allow_private = bool(current_user and settings.ALLOW_PRIVATE_TARGET_SCANS)

    async def stream_response():
        try:
            async for event in stream_os_fingerprint_events(
                body.target, timeout=body.timeout,
                allow_private=allow_private, db_session=db,
            ):
                if event.get("type") == "done":
                    result_dict = dataclasses.asdict(event["result"])
                    tool_result_id = await _save_tool_result(db, current_user, "os_fingerprint", body.target, result_dict)
                    event = {"type": "done", "data": result_dict, "tool_result_id": tool_result_id}
                yield f"data: {json.dumps(event)}\n\n"
        except Exception as e:
            logger.exception("OS fingerprint stream failed for %s", body.target)
            yield f"data: {json.dumps({'type': 'error', 'error': str(e)})}\n\n"

    return StreamingResponse(
        stream_response(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )

@router.post("/port_scan")
async def run_port_scan(
    body: PortScanRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User | None = Depends(get_optional_user)
):
    # Authenticated users may bypass the private-IP block when the setting permits.
    allow_private = bool(current_user and settings.ALLOW_PRIVATE_TARGET_SCANS)

    # Determine scan type based on parameters
    if body.ports:
        # Scan specific ports
        result = await scan_ports(
            body.target,
            ports=body.ports,
            timeout=body.timeout,
            max_concurrent=body.max_concurrent,
            allow_private=allow_private,
            db_session=db,
            include_ai_recommendations=body.include_ai_recommendations,
            include_threat_intel=body.include_threat_intel,
            include_misconfigurations=body.include_misconfigurations,
            include_screenshots=body.include_screenshots,
        )
    elif body.start_port is not None and body.end_port is not None:
        # Scan port range
        result = await scan_port_range(
            body.target,
            start_port=body.start_port,
            end_port=body.end_port,
            timeout=body.timeout,
            max_concurrent=body.max_concurrent,
            allow_private=allow_private,
            db_session=db,
            include_ai_recommendations=body.include_ai_recommendations,
            include_threat_intel=body.include_threat_intel,
            include_misconfigurations=body.include_misconfigurations,
            include_screenshots=body.include_screenshots,
        )
    else:
        # Scan common ports by default
        result = await scan_ports(
            body.target,
            timeout=body.timeout,
            max_concurrent=body.max_concurrent,
            allow_private=allow_private,
            db_session=db,
            include_ai_recommendations=body.include_ai_recommendations,
            include_threat_intel=body.include_threat_intel,
            include_misconfigurations=body.include_misconfigurations,
            include_screenshots=body.include_screenshots,
        )

    result_dict = _port_scan_to_dict(result)
    tool_result_id = await _save_tool_result(db, current_user, "port_scan", body.target, result_dict)
    return {"tool_result_id": tool_result_id, "data": result_dict}


@router.post("/port_scan/stream")
async def stream_port_scan(
    body: PortScanRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User | None = Depends(get_optional_user)
):
    if body.ports:
        ports = body.ports
    elif body.start_port is not None and body.end_port is not None:
        ports = list(range(body.start_port, body.end_port + 1))
    else:
        ports = None

    allow_private = bool(current_user and settings.ALLOW_PRIVATE_TARGET_SCANS)

    async def stream_response():
        try:
            async for event in stream_port_scan_events(
                body.target,
                ports=ports,
                timeout=body.timeout,
                max_concurrent=body.max_concurrent,
                allow_private=allow_private,
                db_session=db,
                include_ai_recommendations=body.include_ai_recommendations,
                include_threat_intel=body.include_threat_intel,
                include_misconfigurations=body.include_misconfigurations,
                include_screenshots=body.include_screenshots,
            ):
                if event.get("type") == "done":
                    result_dict = _port_scan_to_dict(event["result"])
                    tool_result_id = await _save_tool_result(db, current_user, "port_scan", body.target, result_dict)
                    event = {"type": "done", "data": result_dict, "tool_result_id": tool_result_id}
                yield f"data: {json.dumps(event)}\n\n"
        except Exception as e:
            logger.exception("Port scan stream failed for %s", body.target)
            yield f"data: {json.dumps({'type': 'error', 'error': str(e)})}\n\n"

    return StreamingResponse(
        stream_response(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )
