"""Scan result retrieval and export routes."""
import logging
from typing import List

from fastapi import APIRouter, HTTPException
from sqlalchemy import select

from cybersec.apps.api.services.scan_state import scan_meta as _scan_meta, scan_results as _scan_results
from cybersec.config.settings import settings
from cybersec.core.scanner.analysis.service_detect import ServiceDetectionResult
from cybersec.core.security.attack_mapping import enrich_scan_with_attack
from cybersec.core.security.nvd_client import CVEResult
from cybersec.database.models import Scan, ScanResult
from cybersec.database.session import async_session_maker

logger = logging.getLogger(__name__)
router = APIRouter(tags=["scan-results"])


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
    raw_results = _scan_results.get(scan_id, [])
    
    # Final deduplication to prevent duplicate port results
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
        else:
            logger.debug(f"Filtering duplicate result: {port_key}")

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
                "results": results,
                # ADDED: Include stress test metrics if available
                "metrics": meta.get("metrics")
            })
            
            # Add ATT&CK mapping if enabled
            if settings.ENABLE_ATTACK_MAPPING and results:
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
                    enriched_response = enrich_scan_with_attack(response, cve_results, detected_services)
                    response.update(enriched_response)
                    
                except Exception as e:
                    logger.warning(f"ATT&CK mapping failed for scan {scan_id}: {e}")
                    # Continue without ATT&CK mapping
        
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

            from cybersec.core.scanner.analysis.port_analyzer import PortAnalyzer
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
                        # Determine tactics based on technique
                        if "T1021" in technique:
                            tactics = ["Lateral Movement"]
                        elif technique == "T1190":
                            tactics = ["Initial Access"]
                        elif technique == "T1110":
                            tactics = ["Credential Access"]
                        elif technique == "T1078":
                            tactics = ["Initial Access"]
                        elif technique == "T1571":
                            tactics = ["Defense Evasion"]
                        elif technique.startswith("T1048"):
                            tactics = ["Exfiltration"]
                        elif technique in ["T1083", "T1592"]:
                            tactics = ["Discovery"]
                        elif technique in ["T1566.001", "T1595.002"]:
                            tactics = ["Reconnaissance"]
                        elif technique.startswith("T1071"):
                            tactics = ["Command and Control"]
                        elif technique == "T1059.007":
                            tactics = ["Execution"]
                        else:
                            tactics = ["Unknown"]
                        
                        mitre_info.append({
                            "id": technique,
                            "name": mitre_names.get(technique, "Unknown Technique"),
                            "tactics": tactics
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
                        # Determine tactics based on technique
                        if "T1021" in technique:
                            tactics = ["Lateral Movement"]
                        elif technique == "T1190":
                            tactics = ["Initial Access"]
                        elif technique == "T1110":
                            tactics = ["Credential Access"]
                        elif technique == "T1078":
                            tactics = ["Initial Access"]
                        elif technique == "T1571":
                            tactics = ["Defense Evasion"]
                        elif technique.startswith("T1048"):
                            tactics = ["Exfiltration"]
                        elif technique in ["T1083", "T1592"]:
                            tactics = ["Discovery"]
                        elif technique in ["T1566.001", "T1595.002"]:
                            tactics = ["Reconnaissance"]
                        elif technique.startswith("T1071"):
                            tactics = ["Command and Control"]
                        elif technique == "T1059.007":
                            tactics = ["Execution"]
                        else:
                            tactics = ["Unknown"]
                        
                        mitre_info.append({
                            "id": technique,
                            "name": mitre_names.get(technique, "Unknown Technique"),
                            "tactics": tactics
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
):
    """List recent scans from in-memory storage."""
    in_memory_scans = list(_scan_meta.values())[:limit]
    return {
        "scans": in_memory_scans,
        "storage": "in_memory",
    }
