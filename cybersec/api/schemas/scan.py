"""
Scan pydantic schemas.
"""
from pydantic import BaseModel, Field
from typing import Optional, Any, Literal
from uuid import UUID

class ScanCreate(BaseModel):
    target: str
    scan_type: Literal[
        "connect", "syn", "udp",
        "stealth_fin", "stealth_null", "stealth_xmas", "stealth_ack",
        "zombie", "ack", "full"
    ] = "connect"
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
