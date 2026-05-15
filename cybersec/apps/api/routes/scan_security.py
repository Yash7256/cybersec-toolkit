"""OS fingerprinting, CVE, vulnerability, and ATT&CK scan routes."""
import asyncio
import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, WebSocket
from pydantic import BaseModel, Field
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from cybersec.apps.api.deps import get_db, get_optional_user
from cybersec.apps.api.services.scan_state import (
    scan_events as _scan_events,
    scan_meta as _scan_meta,
    scan_results as _scan_results,
)
from cybersec.config.settings import settings
from cybersec.core.scanner import AsyncPortScanner
from cybersec.core.scanner.analysis.service_detect import ServiceDetectionResult
from cybersec.core.scanner.utils import resolve_target
from cybersec.core.security.attack_mapping import enrich_scan_with_attack
from cybersec.core.security.nvd_client import CVEResult
from cybersec.database.models import Scan, ScanResult, ToolResult, User
from cybersec.database.session import async_session_maker

logger = logging.getLogger(__name__)
router = APIRouter(tags=["scan-security"])


class OSFingerprintRequest(BaseModel):
    target: str = Field(min_length=1, max_length=255)


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

    scanner = AsyncPortScanner(timeout=10.0)
    report = await scanner.scan(body.target, port_range="22,80,135,139,445")

    banners = [
        r.service.banner_snippet
        for r in report.open_ports
        if r.service and r.service.banner_snippet
    ]
    
    from cybersec.core.scanner.analysis.os_fingerprint import OSFingerprinter
    fingerprinter = OSFingerprinter()
    
    # Try active fingerprinting first (requires root privileges)
    try:
        fp = fingerprinter.fingerprint_active(body.target, [r.port for r in report.open_ports])
        
        # If active fingerprinting didn't find anything, fall back to banner analysis
        if fp.os_name == "Unknown" or fp.confidence == 0.0:
            logger.info("Active OS fingerprinting returned Unknown, falling back to banner analysis")
            fp = fingerprinter.fingerprint(banners, [r.port for r in report.open_ports])
        else:
            logger.info(f"Active OS fingerprinting successful for {body.target}")
    except PermissionError as e:
        logger.warning(f"Active OS fingerprinting requires root privileges: {e}")
        logger.info("Falling back to banner-based OS fingerprinting")
        fp = fingerprinter.fingerprint(banners, [r.port for r in report.open_ports])
    except Exception as e:
        logger.warning(f"Active OS fingerprinting failed, falling back to banner analysis: {e}")
        fp = fingerprinter.fingerprint(banners, [r.port for r in report.open_ports])

    result_data = {
        "os_name": fp.os_name,
        "confidence": fp.confidence,
        "method": fp.method,
        "vendor": fp.vendor,
        "os_family": fp.os_family,
        "version": fp.version,
        "ambiguous": fp.ambiguous,
        "signals_used": fp.signals_used,
        "hop_count": fp.hop_count,
        "tech_details": {
            "ttl": fp.tech_details.ttl,
            "window_size": fp.tech_details.window_size,
            "df_flag": fp.tech_details.df_flag,
            "tcp_options": fp.tech_details.tcp_options
        },
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
        "confidence_pct": round(fp.confidence, 1),
        "method": fp.method,
        "vendor": fp.vendor,
        "os_family": fp.os_family,
        "version": fp.version,
        "ambiguous": fp.ambiguous,
        "signals_used": fp.signals_used,
        "hop_count": fp.hop_count,
        "tech_details": {
            "ttl": fp.tech_details.ttl,
            "window_size": fp.tech_details.window_size,
            "df_flag": fp.tech_details.df_flag,
            "tcp_options": fp.tech_details.tcp_options
        },
        "open_ports": [r.port for r in report.open_ports],
        "open_ports_scanned": [r.port for r in report.open_ports],  # Keep for backward compatibility
        "scan_duration": report.scan_duration,
        "tool_result_id": tool_result_id,
        "storage": "database" if tool_result_id else "memory",
    }


# ─── SCAN VULNERABILITIES ──────────────────────────────────────────────────────

@router.get("/{scan_id}/vulnerabilities")
async def get_scan_vulnerabilities(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_user),
):
    """Get vulnerability analysis for a completed scan.
    
    This endpoint reads scan results, extracts detected services,
    calls NVD API for CVE lookup, and returns comprehensive vulnerability data.
    """
    try:
        # Get scan from database
        result = await db.execute(
            text("SELECT * FROM scans WHERE id = :scan_id"),
            {"scan_id": scan_id}
        )
        scan_row = result.fetchone()
        
        if not scan_row:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        # Get scan results
        results_result = await db.execute(
            text("""
                SELECT port, protocol, state, service, version, banner, cves 
                FROM scan_results 
                WHERE scan_id = :scan_id AND state = 'open'
                ORDER BY port
            """),
            {"scan_id": scan_id}
        )
        scan_results = results_result.fetchall()
        
        if not scan_results:
            return {
                "scan_id": scan_id,
                "services_analyzed": 0,
                "total_cves_found": 0,
                "results": [],
                "message": "No open ports found in scan"
            }
        
        # Initialize NVD client with database session
        from cybersec.core.security.nvd_client import EnhancedCVELookup
        nvd_lookup = EnhancedCVELookup(db)
        
        vulnerability_results = []
        total_cves = 0
        services_analyzed = 0
        
        for result in scan_results:
            port = result.port
            service_name = result.service or "unknown"
            service_version = result.version or ""
            banner = result.banner or ""
            
            # Skip if service is unknown
            if service_name.lower() in ["unknown", ""]:
                vulnerability_results.append({
                    "port": port,
                    "service": service_name,
                    "version": service_version,
                    "banner": banner,
                    "cves": [],
                    "message": "Service not identified, skipping CVE lookup"
                })
                continue
            
            services_analyzed += 1
            
            try:
                # Look up CVEs for this service
                cves = await nvd_lookup.lookup(service_name, service_version)
                
                # Format CVEs for response
                formatted_cves = []
                for cve in cves:
                    formatted_cve = {
                        "cve_id": cve.get("id", ""),
                        "description": cve.get("description", ""),
                        "published": cve.get("published", ""),
                        "last_modified": cve.get("last_modified", ""),
                        "vuln_status": cve.get("vuln_status", ""),
                        "cvss_v3_score": cve.get("cvss_v3_score"),
                        "cvss_v3_severity": cve.get("cvss_v3_severity"),
                        "cvss_v2_score": cve.get("cvss_v2_score"),
                        "cvss_v3_vector": cve.get("cvss_v3_vector"),
                        "references": cve.get("references", []),
                        "source": cve.get("source", "NVD"),
                        "cvss_score": cve.get("cvss_score", 0.0),
                        "severity": cve.get("severity", "UNKNOWN"),
                        "confidence": cve.get("confidence", 0.9)
                    }
                    formatted_cves.append(formatted_cve)
                
                total_cves += len(formatted_cves)
                
                vulnerability_results.append({
                    "port": port,
                    "service": service_name,
                    "version": service_version,
                    "banner": banner[:100] + "..." if len(banner) > 100 else banner,
                    "cves": formatted_cves,
                    "cve_count": len(formatted_cves),
                    "highest_cvss": max([cve.get("cvss_score", 0.0) for cve in formatted_cves]) if formatted_cves else 0.0,
                    "has_critical": any(cve.get("severity") == "CRITICAL" for cve in formatted_cves),
                    "has_high": any(cve.get("severity") == "HIGH" for cve in formatted_cves)
                })
                
            except Exception as e:
                logger.error(f"CVE lookup failed for {service_name}:{port} - {e}")
                vulnerability_results.append({
                    "port": port,
                    "service": service_name,
                    "version": service_version,
                    "banner": banner,
                    "cves": [],
                    "cve_count": 0,
                    "error": f"CVE lookup failed: {str(e)}"
                })
        
        # Sort results by highest CVSS score
        vulnerability_results.sort(
            key=lambda x: x.get("highest_cvss", 0.0),
            reverse=True
        )
        
        return {
            "scan_id": scan_id,
            "target": scan_row.target,
            "scan_type": scan_row.scan_type,
            "services_analyzed": services_analyzed,
            "total_cves_found": total_cves,
            "critical_cves": len([
                r for r in vulnerability_results 
                if r.get("has_critical", False)
            ]),
            "high_cves": len([
                r for r in vulnerability_results 
                if r.get("has_high", False)
            ]),
            "results": vulnerability_results,
            "scan_completed_at": scan_row.completed_at.isoformat() if scan_row.completed_at else None,
            "storage": "database"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Vulnerability analysis failed for scan {scan_id}: {e}")
        raise HTTPException(status_code=500, detail="Vulnerability analysis failed")


@router.get("/cve/{cve_id}")
async def get_cve_details(
    cve_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_user),
):
    """Get detailed information about a specific CVE."""
    try:
        # Validate CVE ID format
        if not cve_id.startswith("CVE-") or len(cve_id.split("-")) != 3:
            raise HTTPException(status_code=400, detail="Invalid CVE ID format")
        
        # Use NVD client to get CVE details
        from cybersec.core.security.nvd_client import NVDClient
        nvd_client = NVDClient()
        
        cve_result = await nvd_client.get_cve_by_id(cve_id)
        
        if not cve_result:
            raise HTTPException(status_code=404, detail="CVE not found")
        
        return {
            "cve_id": cve_result.cve_id,
            "description": cve_result.description,
            "published": cve_result.published,
            "last_modified": cve_result.last_modified,
            "vuln_status": cve_result.vuln_status,
            "cvss_v3_score": cve_result.cvss_v3_score,
            "cvss_v3_severity": cve_result.cvss_v3_severity,
            "cvss_v2_score": cve_result.cvss_v2_score,
            "cvss_v3_vector": cve_result.cvss_v3_vector,
            "references": cve_result.references,
            "source": cve_result.source
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"CVE lookup failed for {cve_id}: {e}")
        raise HTTPException(status_code=500, detail="CVE lookup failed")


@router.get("/{scan_id}/attack-mapping")
async def get_scan_attack_mapping(scan_id: str):
    """Get ATT&CK technique mappings for a completed scan.
    
    Returns only the attack_techniques block + tactics_summary for a given scan.
    """
    if not settings.ENABLE_ATTACK_MAPPING:
        raise HTTPException(status_code=503, detail="ATT&CK mapping is disabled")
    
    # Get scan results
    meta = _scan_meta.get(scan_id)
    raw_results = _scan_results.get(scan_id, [])
    
    # Deduplicate results for CVE lookup
    seen_ports = set()
    results = []
    for result in raw_results:
        port_key = f"{result.get('port', '')}:{result.get('protocol', 'tcp')}"
        target = result.get('target', '')
        if target:
            port_key = f"{target}:{port_key}"
        
        if port_key not in seen_ports:
            seen_ports.add(port_key)
            results.append(result)
    
    if meta is None:
        # Try database
        try:
            async with async_session_maker() as db:
                scan = await db.get(Scan, scan_id)
                if not scan:
                    raise HTTPException(status_code=404, detail="Scan not found")
                
                results_q = await db.execute(
                    select(ScanResult).where(ScanResult.scan_id == scan_id).order_by(ScanResult.port.asc())
                )
                db_results = results_q.scalars().all()
                
                # Convert DB results to expected format
                results = []
                for r in db_results:
                    results.append({
                        "port": r.port,
                        "protocol": r.protocol,
                        "state": r.state,
                        "service": r.service,
                        "version": r.version,
                        "banner": r.banner,
                        "cves": r.cves or []
                    })
        except Exception as e:
            logger.error(f"Database lookup failed for scan {scan_id}: {e}")
            raise HTTPException(status_code=503, detail="Database unavailable")
    
    if not results:
        return {
            "scan_id": scan_id,
            "attack_techniques": [],
            "tactics_summary": [],
            "attack_technique_count": 0,
            "message": "No open ports found in scan"
        }
    
    try:
        # Convert results to ServiceDetectionResult format
        detected_services = []
        for result in results:
            if result.get("state") == "open":
                service_result = ServiceDetectionResult(
                    port=result.get("port", 0),
                    state=result.get("state", ""),
                    service_name=result.get("service", "unknown"),
                    service_version=result.get("version", ""),
                    detection_method="scan",
                    banner_snippet=result.get("banner", ""),
                    confidence=0.8
                )
                detected_services.append(service_result)
        
        # Extract CVEs from results
        cve_results = []
        for result in results:
            cves = result.get("cves", [])
            for cve in cves:
                cve_result = CVEResult(
                    cve_id=cve.get("id", ""),
                    description=cve.get("description", ""),
                    published="",
                    last_modified="",
                    vuln_status="",
                    cvss_v3_score=cve.get("cvss_score", 0.0),
                    cvss_v3_severity=cve.get("severity", ""),
                    cvss_v2_score=None,
                    cvss_v3_vector=None,
                    references=[],
                    source="scan"
                )
                cve_results.append(cve_result)
        
        # Enrich with ATT&CK data
        enriched_scan = enrich_scan_with_attack({}, cve_results, detected_services)
        
        return {
            "scan_id": scan_id,
            "attack_techniques": enriched_scan.get("attack_techniques", []),
            "tactics_summary": enriched_scan.get("tactics_summary", []),
            "attack_technique_count": enriched_scan.get("attack_technique_count", 0)
        }
        
    except Exception as e:
        logger.error(f"ATT&CK mapping failed for scan {scan_id}: {e}")
        raise HTTPException(status_code=500, detail="ATT&CK mapping failed")


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
