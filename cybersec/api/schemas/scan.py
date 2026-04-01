from datetime import datetime
from enum import Enum
from typing import Optional, Any
from uuid import UUID

from pydantic import BaseModel, Field


class ScanType(str, Enum):
    PORT = "port"
    WEB = "web"
    FULL = "full"


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class ScanCreate(BaseModel):
    target: str = Field(min_length=1, max_length=255)
    scan_type: ScanType = ScanType.PORT
    port_range: Optional[str] = Field(default="common", max_length=100)
    options: Optional[dict[str, Any]] = None


class ScanRead(BaseModel):
    id: UUID
    user_id: Optional[UUID]
    target: str
    scan_type: ScanType
    status: ScanStatus
    port_range: Optional[str]
    options: Optional[dict[str, Any]]
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    created_at: datetime

    model_config = {"from_attributes": True}


class ScanResultRead(BaseModel):
    id: UUID
    scan_id: UUID
    port: Optional[int]
    protocol: Optional[str]
    state: Optional[str]
    service: Optional[str]
    version: Optional[str]
    cves: Optional[list[dict[str, Any]]]
    banner: Optional[str]
    created_at: datetime

    model_config = {"from_attributes": True}


class ScanDetail(BaseModel):
    scan: ScanRead
    results: list[ScanResultRead]


class ScanStatusResponse(BaseModel):
    status: ScanStatus
    progress_pct: float
    open_ports_found: int


class ScanListResponse(BaseModel):
    scans: list[ScanRead]
    total: int
    page: int
    page_size: int
