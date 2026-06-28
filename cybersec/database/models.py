"""
SQLAlchemy database models for CyberSec.
"""
from sqlalchemy import Column, String, Boolean, Enum, Integer, Text, ForeignKey, TIMESTAMP
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship

from cybersec.database.base import Base, UUIDPrimaryKeyMixin, TimestampMixin

class User(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "users"

    email = Column(String(255), unique=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True)
    is_superuser = Column(Boolean, default=False)

class Scan(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "scans"

    user_id = Column(ForeignKey("users.id"), nullable=True)
    target = Column(String(255), nullable=False)
    scan_type = Column(String(50), nullable=False)
    status = Column(
        Enum('pending', 'running', 'completed', 'failed', 'cancelled', 'timed_out',
             name='scan_status_enum'),
        default='pending',
    )
    port_range = Column(String(100), nullable=True)
    options = Column(JSONB, nullable=True)
    started_at = Column(TIMESTAMP(timezone=True), nullable=True)
    completed_at = Column(TIMESTAMP(timezone=True), nullable=True)

    # Distributed state tracking
    heartbeat_at = Column(TIMESTAMP(timezone=True), nullable=True)
    worker_id = Column(String(100), nullable=True)
    progress_pct = Column(Integer, default=0)
    error_message = Column(Text, nullable=True)

class ScanResult(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "scan_results"

    scan_id = Column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    port = Column(Integer, nullable=True)
    protocol = Column(String(10), nullable=True)
    state = Column(String(20), nullable=True)
    service = Column(String(100), nullable=True)
    version = Column(String(255), nullable=True)
    banner = Column(Text, nullable=True)
    cves = Column(JSONB, nullable=True)

class ToolResult(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "tool_results"

    user_id = Column(ForeignKey("users.id"), nullable=True)
    tool_name = Column(String(50), nullable=False)
    target = Column(String(255), nullable=False)
    result_data = Column(JSONB, nullable=False)

class Report(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "reports"

    scan_id = Column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    user_id = Column(ForeignKey("users.id"), nullable=True)
    format = Column(Enum('json', 'csv', 'pdf', name='report_format_enum'), nullable=False)
    file_path = Column(String(500), nullable=True)

class WorkerHeartbeat(Base):
    """Tracks worker process liveness for scan ownership recovery."""
    __tablename__ = "worker_heartbeats"

    worker_id = Column(String(100), primary_key=True)
    hostname = Column(String(255), nullable=True)
    pid = Column(Integer, nullable=True)
    active_scans = Column(Integer, default=0)
    last_heartbeat = Column(TIMESTAMP(timezone=True), nullable=False)


class NVDCveCache(Base):
    __tablename__ = "nvd_cve_cache"
    
    cve_id = Column(String(20), primary_key=True)  # CVE-YYYY-NNNNN format
    data = Column(JSONB, nullable=False)          # full CVEResult as JSON
    fetched_at = Column(TIMESTAMP(timezone=True), nullable=False)
    expires_at = Column(TIMESTAMP(timezone=True), nullable=False)


class NVDServiceLookupCache(Base):
    """Cache for NVDClient.lookup_cves_for_service() results keyed by service/version pair."""
    __tablename__ = "nvd_service_lookup_cache"

    id = Column(Integer, primary_key=True, autoincrement=True)
    cache_key = Column(String(64), unique=True, nullable=False, index=True)  # sha256 hex
    service_name = Column(String(255), nullable=False)
    service_version = Column(String(255), nullable=False)
    results = Column(JSONB, nullable=False)  # list of CVEResult dicts
    fetched_at = Column(TIMESTAMP(timezone=True), nullable=False)
    expires_at = Column(TIMESTAMP(timezone=True), nullable=False)

# TODO: implement relationships and other columns if needed
