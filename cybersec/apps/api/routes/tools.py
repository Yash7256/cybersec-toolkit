"""
Tools router implementation.
"""
import logging
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from cybersec.apps.api.deps import get_db, get_optional_user
from cybersec.database.models import User, ToolResult
import dataclasses

from cybersec.apps.api.schemas.tool import (
    DnsRequest, WhoisRequest, PingRequest, TracerouteRequest,
    SslRequest, HttpHeadersRequest, SubdomainRequest, GeoipRequest,
    PortScanRequest, ToolResultOut
)

from cybersec.core.tools.dns import dns_lookup
from cybersec.core.tools.whois import whois_lookup
from cybersec.core.tools.ping import ping_host
from cybersec.core.tools.traceroute import traceroute
from cybersec.core.tools.ssl import ssl_audit
from cybersec.core.tools.http_headers import check_http_headers
from cybersec.core.tools.subdomain import find_subdomains
from cybersec.core.tools.geoip import geoip_lookup
from cybersec.core.tools.port_scanner import scan_ports, scan_port_range

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

@router.post("/port_scan")
async def run_port_scan(
    body: PortScanRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User | None = Depends(get_optional_user)
):
    # Determine scan type based on parameters
    if body.ports:
        # Scan specific ports
        result = await scan_ports(
            body.target, 
            ports=body.ports,
            timeout=body.timeout,
            max_concurrent=body.max_concurrent
        )
    elif body.start_port is not None and body.end_port is not None:
        # Scan port range
        result = await scan_port_range(
            body.target,
            start_port=body.start_port,
            end_port=body.end_port,
            timeout=body.timeout,
            max_concurrent=body.max_concurrent
        )
    else:
        # Scan common ports by default
        result = await scan_ports(
            body.target,
            timeout=body.timeout,
            max_concurrent=body.max_concurrent
        )
    
    result_dict = dataclasses.asdict(result)
    tool_result_id = await _save_tool_result(db, current_user, "port_scan", body.target, result_dict)
    return {"tool_result_id": tool_result_id, "data": result_dict}
