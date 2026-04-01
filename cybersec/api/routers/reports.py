import csv
import io
import logging
from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, HTTPException, status
from fastapi.responses import StreamingResponse
from sqlalchemy import select

from cybersec.api.deps import DBSession, OptionalUser
from cybersec.api.schemas.scan import ScanRead, ScanResultRead
from cybersec.database.models import Scan, ScanResult

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("/scan/{scan_id}/json")
async def export_scan_json(
    scan_id: UUID,
    db: DBSession,
    current_user: OptionalUser,
) -> dict:
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        )

    if current_user and scan.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to export this scan",
        )

    results_result = await db.execute(
        select(ScanResult).where(ScanResult.scan_id == scan_id)
    )
    results = results_result.scalars().all()

    return {
        "scan": ScanRead.model_validate(scan).model_dump(mode="json"),
        "results": [
            ScanResultRead.model_validate(r).model_dump(mode="json")
            for r in results
        ],
        "exported_at": datetime.utcnow().isoformat(),
    }


@router.get("/scan/{scan_id}/csv")
async def export_scan_csv(
    scan_id: UUID,
    db: DBSession,
    current_user: OptionalUser,
) -> StreamingResponse:
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        )

    if current_user and scan.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to export this scan",
        )

    results_result = await db.execute(
        select(ScanResult).where(ScanResult.scan_id == scan_id)
    )
    results = results_result.scalars().all()

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "port", "protocol", "state", "service", "version", "banner", "cves"
    ])

    for r in results:
        writer.writerow([
            r.port,
            r.protocol,
            r.state,
            r.service,
            r.version or "",
            r.banner or "",
            str(r.cves) if r.cves else "",
        ])

    output.seek(0)

    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={
            "Content-Disposition": f"attachment; filename=scan_{scan_id}.csv"
        },
    )


@router.get("/scan/{scan_id}/pdf")
async def export_scan_pdf(
    scan_id: UUID,
    db: DBSession,
    current_user: OptionalUser,
) -> StreamingResponse:
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        )

    if current_user and scan.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to export this scan",
        )

    results_result = await db.execute(
        select(ScanResult).where(ScanResult.scan_id == scan_id)
    )
    results = results_result.scalars().all()

    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib import colors
    from reportlab.lib.units import inch

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    story.append(Paragraph(f"Security Scan Report - {scan.target}", styles["Title"]))
    story.append(Spacer(1, 0.2 * inch))
    story.append(Paragraph(f"Scan ID: {scan.id}", styles["Normal"]))
    story.append(Paragraph(f"Type: {scan.scan_type}", styles["Normal"]))
    story.append(Paragraph(f"Status: {scan.status}", styles["Normal"]))
    story.append(Paragraph(
        f"Created: {scan.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')}",
        styles["Normal"],
    ))
    story.append(Spacer(1, 0.3 * inch))

    if results:
        table_data = [["Port", "Protocol", "State", "Service", "Version"]]
        for r in results[:50]:
            table_data.append([
                str(r.port or ""),
                r.protocol or "",
                r.state or "",
                r.service or "",
                r.version or "",
            ])

        if len(results) > 50:
            table_data.append(["...", "...", "...", "...", "..."])

        table = Table(table_data, colWidths=[1 * inch, 1 * inch, 1 * inch, 2 * inch, 1.5 * inch])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 10),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
            ("BACKGROUND", (0, 1), (-1, -1), colors.beige),
            ("GRID", (0, 0), (-1, -1), 1, colors.black),
        ]))
        story.append(table)
    else:
        story.append(Paragraph("No results found for this scan.", styles["Normal"]))

    doc.build(story)
    buffer.seek(0)

    return StreamingResponse(
        iter([buffer.getvalue()]),
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=scan_{scan_id}.pdf"
        },
    )
