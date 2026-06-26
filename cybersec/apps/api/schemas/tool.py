"""
Tool pydantic schemas.
"""
import ipaddress

from pydantic import BaseModel, ConfigDict, Field, field_validator
from uuid import UUID
from typing import Any, Literal
from datetime import datetime

class DnsRequest(BaseModel):
    target: str
    record_type: str = "ALL"
    
class WhoisRequest(BaseModel):
    target: str = Field(
        min_length=1,
        max_length=253,
        strip_whitespace=True,
        description="Domain name or IP address to look up",
    )
    
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

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("domain is required")
        if len(v) > 253:
            raise ValueError("domain is too long")
        if any(ch.isspace() for ch in v):
            raise ValueError("domain must not contain whitespace")
        # Reject bare IP addresses — this field is a base domain to enumerate
        # subdomains under, not a single target. An IP produces nonsense like
        # "www.8.8.8.8" and is not a valid DNS parent zone.
        try:
            ipaddress.ip_address(v)
            raise ValueError("domain must be a hostname, not an IP address")
        except ValueError as exc:
            if "must be a hostname" in str(exc):
                raise
            # Not a valid IP address — this is what we want; fall through.
        return v.lower()
    
class GeoipRequest(BaseModel):
    target: str

class OsFingerprintRequest(BaseModel):
    target: str
    timeout: float = Field(default=2.0, ge=0.5, le=10.0)

class PortScanRequest(BaseModel):
    target: str
    ports: list[int] | None = None
    start_port: int | None = None
    end_port: int | None = None
    timeout: float = Field(default=2.0, ge=0.1, le=10.0)
    max_concurrent: int = Field(default=100, ge=1, le=2000)


class OpenPortOut(BaseModel):
    port_number: int
    service: str
    status: str
    version: str | None = None
    raw_banner: str | None = None
    welcome_message: str | None = None
    server_response: str | None = None
    risk_level: str = "medium"
    risk_reason: str | None = None
    service_description: str | None = None
    service_security_concern: str | None = None
    technologies: list[str] = Field(default_factory=list)
    screenshot: str | None = None
    screenshot_url: str | None = None
    recommendation: str | None = None
    recommendation_reason: str | None = None
    recommendation_priority: str | None = None
    mitre_attack: list[dict[str, Any]] = Field(default_factory=list)
    potential_threat: str | None = None
    exploit_availability: dict[str, Any] = Field(default_factory=dict)
    misconfigurations: list[dict[str, Any]] = Field(default_factory=list)
    exposure_severity: dict[str, Any] = Field(default_factory=dict)
    cve_result: dict[str, Any] | None = None
    cve_count: int = 0
    cve_critical_count: int = 0
    cve_high_count: int = 0
    cve_medium_count: int = 0
    cve_low_count: int = 0
    max_cvss_score: float | None = None
    max_cvss_severity: str | None = None
    max_cvss_cve: str | None = None
    fingerprint: dict[str, Any] = Field(default_factory=dict)


class SecurityScoreFactorOut(BaseModel):
    category: str
    label: str
    penalty: int
    severity: str = "medium"


class AttackSurfaceOut(BaseModel):
    level: str = "LOW"
    score: int = 0
    publicly_exposed_services: list[dict[str, Any]] = Field(default_factory=list)
    factors: list[dict[str, Any]] = Field(default_factory=list)
    summary: str = ""


class PortScanOut(BaseModel):
    target: str
    total_scanned: int
    open_ports_count: int
    open_ports: list[OpenPortOut]
    detected_technologies: list[str] = Field(default_factory=list)
    scan_duration_seconds: float
    packets_sent: int = 0
    avg_latency_ms: float | None = None
    security_score: int = 100
    security_score_factors: list[SecurityScoreFactorOut] = Field(default_factory=list)
    attack_surface: AttackSurfaceOut = Field(default_factory=AttackSurfaceOut)
    threat_intelligence: dict[str, Any] = Field(default_factory=dict)
    misconfiguration_summary: dict[str, Any] = Field(default_factory=dict)
    exposure_summary: dict[str, Any] = Field(default_factory=dict)
    attack_paths: dict[str, Any] = Field(default_factory=dict)
    attack_simulations: list[dict[str, Any]] = Field(default_factory=list)
    recommendations_error: str | None = None
    error: str | None = None

class ToolResultOut(BaseModel):
    id: UUID
    tool_name: str
    target: str
    result_data: dict[str, Any]
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
