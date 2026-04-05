"""
Scan pydantic schemas.
"""
from pydantic import BaseModel
from typing import Optional, Any
from uuid import UUID

class ScanCreate(BaseModel):
    target: str
    scan_type: str
    port_range: Optional[str] = None
    options: Optional[dict[str, Any]] = None

class ScanOut(BaseModel):
    id: UUID
    target: str
    scan_type: str
    status: str

    class Config:
        from_attributes = True

class ScanStatusOut(BaseModel):
    status: str
    progress_pct: int
    open_ports_found: int

# TODO: implement additional schemas
