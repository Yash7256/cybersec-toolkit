from typing import Any, Optional
from uuid import UUID

from pydantic import BaseModel, Field


class ToolRequest(BaseModel):
    target: str = Field(min_length=1, max_length=255)
    options: Optional[dict[str, Any]] = None


class ToolResultRead(BaseModel):
    id: UUID
    tool_name: str
    target: str
    result_data: dict[str, Any]
    created_at: str


class DNSRequest(BaseModel):
    target: str = Field(min_length=1, max_length=255)
    record_type: str = Field(default="A", max_length=10)


class WHOISRequest(BaseModel):
    target: str = Field(min_length=1, max_length=255)


class SSLRequest(BaseModel):
    target: str = Field(min_length=1, max_length=255)
    port: int = Field(default=443, ge=1, le=65535)


class HTTPHeadersRequest(BaseModel):
    target: str = Field(min_length=1, max_length=255)
    path: str = Field(default="/")


class TracerouteRequest(BaseModel):
    target: str = Field(min_length=1, max_length=255)
    max_hops: int = Field(default=30, ge=1, le=64)


class PingRequest(BaseModel):
    target: str = Field(min_length=1, max_length=255)
    count: int = Field(default=4, ge=1, le=100)


class SubdomainRequest(BaseModel):
    domain: str = Field(min_length=1, max_length=255)
    wordlist: Optional[str] = None


class GeoIPRequest(BaseModel):
    target: str = Field(min_length=1, max_length=255)
