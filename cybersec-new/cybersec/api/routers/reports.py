"""
Reports router implementation.
"""
from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from uuid import UUID
import json
import csv
import io
from datetime import datetime

from cybersec.api.deps import get_db, get_optional_user
from cybersec.database.models import Scan, ScanResult, Report, User

router = APIRouter()

async def load_scan_with_results(scan_id: UUID, db: AsyncSession) -> tuple[Scan, list[ScanResult]]:
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
        
    results = await db.execute(
        select(ScanResult)
        .where(ScanResult.scan_id == scan_id)
        .order_by(ScanResult.port.asc())
    )
    return scan, list(results.scalars().all())

@router.get("/scan/{scan_id}/json")
async def export_json(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User | None = Depends(get_optional_user)
):
    scan, results = await load_scan_with_results(scan_id, db)
    
    duration_seconds = None
    if scan.started_at and scan.completed_at:
        duration_seconds = (scan.completed_at - scan.started_at).total_seconds()
        
    critical_cves = 0
    high_cves = 0
    services_found = set()
    open_ports = 0
    
    formatted_results = []
    
    for r in results:
        if r.state and r.state.lower() == "open":
            open_ports += 1
            if r.service:
                services_found.add(r.service)
                
        cves = r.cves or []
        if callable(getattr(cves, "get", None)):
            cves = []  # Fallback
        elif not isinstance(cves, list):
            cves = [cves] if cves else []
            
        for c in cves:
            sev = c.get("severity", "").upper()
            if sev == "CRITICAL":
                critical_cves += 1
            elif sev == "HIGH":
                high_cves += 1
                
        formatted_results.append({
            "port": r.port,
            "protocol": r.protocol,
            "state": r.state,
            "service": r.service,
            "version": r.version,
            "banner": r.banner,
            "cves": r.cves or []
        })

    data = {
        "scan": {
            "id": str(scan.id),
            "target": scan.target,
            "scan_type": scan.scan_type,
            "status": scan.status,
            "port_range": scan.port_range,
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            "created_at": scan.created_at.isoformat() if scan.created_at else None,
            "duration_seconds": duration_seconds
        },
        "summary": {
            "total_open_ports": open_ports,
            "total_results": len(results),
            "services_found": list(services_found),
            "critical_cves": critical_cves,
            "high_cves": high_cves
        },
        "results": formatted_results
    }
    
    json_string = json.dumps(data, indent=2, default=str)
    
    report = Report(scan_id=scan.id, user_id=current_user.id if current_user else None, format="json")
    db.add(report)
    await db.commit()
    
    return Response(
        content=json_string,
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="scan_{scan_id}.json"'
        }
    )

@router.get("/scan/{scan_id}/csv")
async def export_csv(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User | None = Depends(get_optional_user)
):
    scan, results = await load_scan_with_results(scan_id, db)
    
    open_ports = sum(1 for r in results if r.state and r.state.lower() == "open")
    
    csv_buffer = io.StringIO()
    
    csv_buffer.write("# CyberSec Scan Report\n")
    csv_buffer.write(f"# Target: {scan.target}\n")
    csv_buffer.write(f"# Date: {scan.created_at}\n")
    csv_buffer.write(f"# Status: {scan.status}\n")
    csv_buffer.write(f"# Total Open Ports: {open_ports}\n")
    
    fieldnames = ["port", "protocol", "state", "service", "version", "banner", "cve_ids", "cve_scores", "risk_level"]
    writer = csv.DictWriter(csv_buffer, fieldnames=fieldnames)
    writer.writeheader()
    
    for r in results:
        cves = r.cves or []
        if callable(getattr(cves, "get", None)):
            cves = []
        elif not isinstance(cves, list):
            cves = [cves] if cves else []
            
        cve_ids = "|".join([c.get("id", "") for c in cves if c.get("id")])
        cve_scores = "|".join([str(c.get("cvss_score", "")) for c in cves if c.get("cvss_score")])
        
        highest_risk = ""
        severities = [c.get("severity", "").upper() for c in cves if c.get("severity")]
        if "CRITICAL" in severities:
            highest_risk = "CRITICAL"
        elif "HIGH" in severities:
            highest_risk = "HIGH"
        elif "MEDIUM" in severities:
            highest_risk = "MEDIUM"
        elif "LOW" in severities:
            highest_risk = "LOW"
        else:
            if cves: highest_risk = "INFO"
            
        writer.writerow({
            "port": r.port,
            "protocol": r.protocol,
            "state": r.state,
            "service": r.service,
            "version": r.version,
            "banner": r.banner if r.banner else "",
            "cve_ids": cve_ids,
            "cve_scores": cve_scores,
            "risk_level": highest_risk
        })
        
    report = Report(scan_id=scan.id, user_id=current_user.id if current_user else None, format="csv")
    db.add(report)
    await db.commit()
    
    return Response(
        content=csv_buffer.getvalue(),
        media_type="text/csv",
        headers={
           "Content-Disposition": f'attachment; filename="scan_{scan_id}.csv"'
        }
    )

@router.get("/scan/{scan_id}/pdf")
async def export_pdf(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User | None = Depends(get_optional_user)
):
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.colors import HexColor
    from reportlab.lib.units import cm
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    
    scan, results = await load_scan_with_results(scan_id, db)
    
    PURPLE   = HexColor("#8B7FEB")
    DARK_BG  = HexColor("#1A1B2E")
    WHITE    = HexColor("#E5E7EB")
    GRAY     = HexColor("#9AA0B4")
    RED      = HexColor("#EF4444")
    ORANGE   = HexColor("#F97316")
    YELLOW   = HexColor("#EAB308")
    GREEN    = HexColor("#22C55E")

    def add_page_number(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 9)
        canvas.drawCentredString(A4[0]/2, 1.5*cm, f"Page {doc.page}")
        canvas.restoreState()

    pdf_buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        pdf_buffer,
        pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm,
        topMargin=2*cm, bottomMargin=2*cm
    )
    
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'TitleStyle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=24,
        textColor=PURPLE,
        spaceAfter=6
    )
    subtitle_style = ParagraphStyle(
        'SubtitleStyle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=14,
        textColor=WHITE,
        spaceAfter=12
    )
    section_style = ParagraphStyle(
        'SectionStyle',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=16,
        textColor=PURPLE,
        spaceBefore=18,
        spaceAfter=12
    )
    normal_style = ParagraphStyle(
        'NormalStyle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        spaceAfter=6
    )
    
    story = []
    
    # 1. COVER SECTION
    story.append(Paragraph("⚡ CyberSec", title_style))
    story.append(Paragraph("Security Scan Report", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=2, color=PURPLE, spaceAfter=20, spaceBefore=10))
    
    duration_str = "None"
    if scan.started_at and scan.completed_at:
        seconds = (scan.completed_at - scan.started_at).total_seconds()
        duration_str = f"{seconds:.2f} seconds"
            
    meta_data = [
        ["Target:", scan.target],
        ["Scan Type:", scan.scan_type if scan.scan_type else "None"],
        ["Status:", scan.status if scan.status else "None"],
        ["Date:", scan.created_at.isoformat() if scan.created_at else "None"],
        ["Duration:", duration_str],
        ["Port Range:", scan.port_range if scan.port_range else "None"]
    ]
    meta_table = Table(meta_data, colWidths=[100, 300])
    meta_table.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 12))
    
    # Analyze results
    open_ports = [r for r in results if r.state and r.state.lower() == "open"]
    
    total_cves = 0
    has_critical = False
    has_high = False
    has_medium = False
    
    all_cves_list = []
    
    for r in open_ports:
        c = r.cves or []
        if isinstance(c, list):
            for i in c:
                i['port'] = r.port
                i['service'] = r.service
                all_cves_list.append(i)
                total_cves += 1
                sev = i.get('severity', '').upper()
                if sev == 'CRITICAL': has_critical = True
                elif sev == 'HIGH': has_high = True
                elif sev == 'MEDIUM': has_medium = True

    overall_risk = "LOW"
    if has_critical: overall_risk = "CRITICAL"
    elif has_high: overall_risk = "HIGH"
    elif has_medium: overall_risk = "MEDIUM"
                
    # 2. EXECUTIVE SUMMARY
    story.append(Paragraph("Executive Summary", section_style))
    
    port_color = GREEN if len(open_ports) == 0 else (ORANGE if len(open_ports) < 10 else RED)
    cve_color = RED if has_critical else GRAY
    risk_color = RED if overall_risk == 'CRITICAL' else (ORANGE if overall_risk == 'HIGH' else (YELLOW if overall_risk == 'MEDIUM' else GRAY))
    
    exec_data = [
        ["Open Ports", str(len(open_ports))],
        ["Total Scanned", str(len(results))],
        ["CVEs Found", str(total_cves)],
        ["Risk Level", overall_risk]
    ]
    
    exec_table = Table(exec_data, colWidths=[150, 150])
    exec_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, 0), port_color),
        ('TEXTCOLOR', (0, 0), (0, 0), WHITE),
        ('BACKGROUND', (1, 0), (1, 0), port_color),
        ('TEXTCOLOR', (1, 0), (1, 0), WHITE),
        
        ('BACKGROUND', (0, 1), (0, 1), GRAY),
        ('TEXTCOLOR', (0, 1), (0, 1), WHITE),
        ('BACKGROUND', (1, 1), (1, 1), GRAY),
        ('TEXTCOLOR', (1, 1), (1, 1), WHITE),
        
        ('BACKGROUND', (0, 2), (0, 2), cve_color),
        ('TEXTCOLOR', (0, 2), (0, 2), WHITE),
        ('BACKGROUND', (1, 2), (1, 2), cve_color),
        ('TEXTCOLOR', (1, 2), (1, 2), WHITE),
        
        ('BACKGROUND', (0, 3), (0, 3), risk_color),
        ('TEXTCOLOR', (0, 3), (0, 3), WHITE),
        ('BACKGROUND', (1, 3), (1, 3), risk_color),
        ('TEXTCOLOR', (1, 3), (1, 3), WHITE),
        
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
        ('GRID', (0, 0), (-1, -1), 1, WHITE),
        ('PADDING', (0, 0), (-1, -1), 8),
    ]))
    story.append(exec_table)
    story.append(Spacer(1, 12))
    
    def get_risk_color(cves):
        highest = "LOW"
        cves = cves or []
        for cve in cves:
            sev = cve.get("severity", "").upper()
            if sev == "CRITICAL": return RED
            if sev == "HIGH": highest = "HIGH"
            elif sev == "MEDIUM" and highest not in ["HIGH"]: highest = "MEDIUM"
        if highest == "HIGH": return ORANGE
        if highest == "MEDIUM": return YELLOW
        return GREEN if len(cves) == 0 else GRAY

    # 3. OPEN PORTS DETAIL
    story.append(Paragraph("Open Ports & Services", section_style))
    if not open_ports:
        story.append(Paragraph("No open ports discovered.", normal_style))
    else:
        port_data = [["Port", "Protocol", "Service", "Version", "Risk"]]
        port_style = TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), DARK_BG),
            ('TEXTCOLOR', (0, 0), (-1, 0), WHITE),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, GRAY),
        ])
        
        for i, r in enumerate(open_ports, start=1):
            r_cves = r.cves or []
            if not isinstance(r_cves, list):
                r_cves = [r_cves] if r_cves else []
            r_color = get_risk_color(r_cves)
            
            p_risk = "INFO"
            if r_color == RED: p_risk = "CRITICAL"
            elif r_color == ORANGE: p_risk = "HIGH"
            elif r_color == YELLOW: p_risk = "MEDIUM"
            elif r_color == GREEN: p_risk = "LOW"
            
            port_data.append([
                str(r.port),
                r.protocol or "",
                r.service or "",
                r.version or "",
                p_risk
            ])
            port_style.add('BACKGROUND', (4, i), (4, i), r_color)
            if r_color in (RED, ORANGE, GREEN, GRAY):
                port_style.add('TEXTCOLOR', (4, i), (4, i), WHITE)
                
        p_table = Table(port_data, colWidths=[50, 70, 100, 150, 80])
        p_table.setStyle(port_style)
        story.append(p_table)
        
    story.append(Spacer(1, 12))
    
    # 4. CVE FINDINGS
    story.append(Paragraph("CVE Findings", section_style))
    if not all_cves_list:
        story.append(Paragraph("No CVEs identified.", normal_style))
    else:
        cve_data = [["Port", "CVE ID", "CVSS", "Severity", "Description"]]
        cve_style = TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), DARK_BG),
            ('TEXTCOLOR', (0, 0), (-1, 0), WHITE),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, GRAY),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ])
        
        for i, cve in enumerate(all_cves_list, start=1):
            sev = cve.get("severity", "").upper()
            c_color = GRAY
            if sev == "CRITICAL": c_color = RED
            elif sev == "HIGH": c_color = ORANGE
            elif sev == "MEDIUM": c_color = YELLOW
            elif sev == "LOW": c_color = GREEN
            
            desc = cve.get('description', '')
            if len(desc) > 100: desc = desc[:100] + "..."
            
            cve_data.append([
                str(cve.get("port", "")),
                cve.get("id", ""),
                str(cve.get("cvss_score", "")),
                sev,
                Paragraph(desc, normal_style)
            ])
            
            cve_style.add('BACKGROUND', (3, i), (3, i), c_color)
            if c_color in (RED, ORANGE, GREEN, GRAY, YELLOW):
                cve_style.add('TEXTCOLOR', (3, i), (3, i), WHITE)
                
        c_table = Table(cve_data, colWidths=[40, 90, 40, 70, 200])
        c_table.setStyle(cve_style)
        story.append(c_table)

    story.append(Spacer(1, 12))

    # 5. RECOMMENDATIONS
    story.append(Paragraph("Recommendations", section_style))
    recs = []
    
    for r in open_ports:
        r_cves = r.cves or []
        if not isinstance(r_cves, list): r_cves = [r_cves] if r_cves else []
        for c in r_cves:
            sev = c.get("severity", "").upper()
            if sev == "CRITICAL":
                recs.append(f"Immediately disable or firewall port {r.port} ({r.service})")
            elif sev == "HIGH":
                recs.append(f"Patch {r.service} — {c.get('id')} (CVSS {c.get('cvss_score')})")
                
        if r.service and r.service.lower() == "telnet":
            recs.append("Replace Telnet with SSH immediately")
        if r.service and r.service.lower() == "ftp":
            recs.append("Replace FTP with SFTP")
            
    if not recs:
        recs.append("No critical issues found. Maintain current security posture.")
        
    seen = set()
    dedup_recs = []
    for r in recs:
        if r not in seen:
            seen.add(r)
            dedup_recs.append(r)
            
    for i, rec in enumerate(dedup_recs, start=1):
        story.append(Paragraph(f"{i}. {rec}", normal_style))
        
    doc.build(story, onFirstPage=add_page_number, onLaterPages=add_page_number)
    
    report = Report(scan_id=scan.id, user_id=current_user.id if current_user else None, format="pdf")
    db.add(report)
    await db.commit()
    
    return Response(
        content=pdf_buffer.getvalue(),
        media_type="application/pdf",
        headers={
           "Content-Disposition": f'attachment; filename="scan_{scan_id}.pdf"'
        }
    )
