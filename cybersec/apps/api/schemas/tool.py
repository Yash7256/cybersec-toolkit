"""
Tool pydantic schemas.
"""
from pydantic import BaseModel, ConfigDict, Field
from uuid import UUID
from typing import Any, Literal
from datetime import datetime

class DnsRequest(BaseModel):
    target: str
    record_type: str = "ALL"
    
class WhoisRequest(BaseModel):
    target: str
    
class PingRequest(BaseModel):
    target: str
    count: int = Field(default=4, ge=1, le=100)
    
class TracerouteRequest(BaseModel):
    target: str
    max_hops: int = Field(default=30, ge=1, le=64)
    
class SslRequest(BaseModel):
    host: str
    port: int = 443
    
class HttpHeadersRequest(BaseModel):
    target: str
    path: str = "/"
    
class SubdomainRequest(BaseModel):
    domain: str
    wordlist: Literal["small", "medium", "large"] = "small"
    strictness: Literal["off", "low", "medium", "high"] = "medium"
    
class GeoipRequest(BaseModel):
    target: str

class PortScanRequest(BaseModel):
    target: str
    ports: list[int] | None = None
    start_port: int | None = None
    end_port: int | None = None
    timeout: float = Field(default=2.0, ge=0.1, le=10.0)
    max_concurrent: int = Field(default=100, ge=1, le=2000)

class ToolResultOut(BaseModel):
    id: UUID
    tool_name: str
    target: str
    result_data: dict[str, Any]
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
