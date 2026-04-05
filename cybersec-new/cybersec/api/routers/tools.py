"""
Tools router implementation.
"""
import logging
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from cybersec.api.deps import get_db, get_optional_user
from cybersec.database.models import User, ToolResult
import dataclasses

from cybersec.api.schemas.tool import (
    DnsRequest, WhoisRequest, PingRequest, TracerouteRequest,
    SslRequest, HttpHeadersRequest, SubdomainRequest, GeoipRequest,
    ToolResultOut
)

from cybersec.core.tools.dns import dns_lookup
from cybersec.core.tools.whois import whois_lookup
from cybersec.core.tools.ping import ping_host
from cybersec.core.tools.traceroute import traceroute
from cybersec.core.tools.ssl import ssl_audit
from cybersec.core.tools.http_headers import check_http_headers
from cybersec.core.tools.subdomain import find_subdomains
from cybersec.core.tools.geoip import geoip_lookup

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
    result = await find_subdomains(body.domain, body.wordlist)
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
