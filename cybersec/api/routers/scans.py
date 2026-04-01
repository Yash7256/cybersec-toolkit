import logging
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, HTTPException, status, BackgroundTasks
from sqlalchemy import select, func

from cybersec.api.deps import DBSession, OptionalUser
from cybersec.api.schemas.scan import (
    ScanCreate,
    ScanRead,
    ScanDetail,
    ScanStatusResponse,
    ScanListResponse,
    ScanStatus,
)
from cybersec.core.scanner import AsyncPortScanner
from cybersec.core.utils import resolve_target
from cybersec.database.models import Scan, ScanResult

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/scans", tags=["scans"])

scanner = AsyncPortScanner()


async def run_scan_background(scan_id: UUID) -> None:
    from cybersec.database.session import get_session_maker

    session_maker = get_session_maker()

    async with session_maker() as db:
        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one_or_none()

        if not scan:
            logger.error(f"Scan {scan_id} not found")
            return

        scan.status = ScanStatus.RUNNING.value
        await db.commit()

        try:
            report = await scanner.scan(
                target=scan.target,
                ports=scan.port_range or "common",
                protocol="tcp",
                timeout=1.0,
                concurrency=500,
            )

            for port_result in report.open_ports:
                scan_result = ScanResult(
                    scan_id=scan_id,
                    port=port_result.port,
                    protocol=port_result.protocol,
                    state=port_result.state,
                    service=port_result.service,
                    version=port_result.version,
                    banner=port_result.banner,
                    cves=[cve.__dict__ for cve in port_result.cves]
                    if port_result.cves
                    else None,
                )
                db.add(scan_result)

            scan.status = ScanStatus.COMPLETED.value
            scan.completed_at = report.timestamp
            await db.commit()

            logger.info(
                f"Scan {scan_id} completed with {len(report.open_ports)} open ports"
            )

        except Exception as e:
            logger.error(f"Scan {scan_id} failed: {e}")
            scan.status = ScanStatus.FAILED.value
            scan.completed_at = report.timestamp if "report" in locals() else None
            await db.commit()


@router.post("/", response_model=ScanRead, status_code=status.HTTP_201_CREATED)
async def create_scan(
    scan_create: ScanCreate,
    db: DBSession,
    current_user: OptionalUser,
    background_tasks: BackgroundTasks,
) -> Scan:
    try:
        resolve_target(scan_create.target)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid target: {e}",
        )

    scan = Scan(
        user_id=current_user.id if current_user else None,
        target=scan_create.target,
        scan_type=scan_create.scan_type.value,
        status=ScanStatus.PENDING.value,
        port_range=scan_create.port_range,
        options=scan_create.options,
    )

    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    background_tasks.add_task(run_scan_background, scan.id)

    return scan


@router.get("/", response_model=ScanListResponse)
async def list_scans(
    db: DBSession,
    current_user: OptionalUser,
    status_filter: Optional[ScanStatus] = None,
    page: int = 1,
    page_size: int = 20,
) -> ScanListResponse:
    query = select(Scan)

    if current_user:
        query = query.where(Scan.user_id == current_user.id)

    if status_filter:
        query = query.where(Scan.status == status_filter.value)

    count_query = select(func.count()).select_from(query.subquery())
    total_result = await db.execute(count_query)
    total = total_result.scalar() or 0

    query = query.order_by(Scan.created_at.desc())
    query = query.offset((page - 1) * page_size).limit(page_size)

    result = await db.execute(query)
    scans = result.scalars().all()

    return ScanListResponse(
        scans=list(scans),
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/{scan_id}", response_model=ScanDetail)
async def get_scan(
    scan_id: UUID,
    db: DBSession,
    current_user: OptionalUser,
) -> ScanDetail:
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
            detail="Not authorized to access this scan",
        )

    results_result = await db.execute(
        select(ScanResult).where(ScanResult.scan_id == scan_id)
    )
    results = results_result.scalars().all()

    return ScanDetail(scan=scan, results=list(results))


@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scan(
    scan_id: UUID,
    db: DBSession,
    current_user: OptionalUser,
) -> None:
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
            detail="Not authorized to delete this scan",
        )

    await db.delete(scan)
    await db.commit()


@router.get("/{scan_id}/status", response_model=ScanStatusResponse)
async def get_scan_status(
    scan_id: UUID,
    db: DBSession,
    current_user: OptionalUser,
) -> ScanStatusResponse:
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
            detail="Not authorized to access this scan",
        )

    open_count_result = await db.execute(
        select(func.count())
        .select_from(ScanResult)
        .where(
            ScanResult.scan_id == scan_id,
            ScanResult.state == "open",
        )
    )
    open_ports_found = open_count_result.scalar() or 0

    progress_pct = 0.0
    if scan.status == ScanStatus.COMPLETED.value:
        progress_pct = 100.0
    elif scan.status == ScanStatus.RUNNING.value:
        progress_pct = 50.0
    elif scan.status == ScanStatus.PENDING.value:
        progress_pct = 0.0

    return ScanStatusResponse(
        status=ScanStatus(scan.status),
        progress_pct=progress_pct,
        open_ports_found=open_ports_found,
    )
