import uuid
import enum
from datetime import datetime

from sqlalchemy import String, DateTime, ForeignKey, Enum, JSON
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from cybersec.database.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class ScanType(str, enum.Enum):
    PORT = "port"
    WEB = "web"
    FULL = "full"


class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class Scan(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "scans"
    __table_args__ = {"schema": None}

    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    target: Mapped[str] = mapped_column(String(255), nullable=False)
    scan_type: Mapped[ScanType] = mapped_column(
        Enum(ScanType, name="scan_type_enum", create_constraint=True),
        nullable=False,
    )
    status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus, name="scan_status_enum", create_constraint=True),
        default=ScanStatus.PENDING,
        index=True,
    )
    port_range: Mapped[str | None] = mapped_column(String(100), nullable=True)
    options: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    user: Mapped["User"] = relationship("User", back_populates="scans")
    results: Mapped[list["ScanResult"]] = relationship(
        "ScanResult", back_populates="scan", cascade="all, delete-orphan"
    )
    tool_results: Mapped[list["ToolResult"]] = relationship(
        "ToolResult", back_populates="scan", cascade="all, delete-orphan"
    )
    reports: Mapped[list["Report"]] = relationship(
        "Report", back_populates="scan", cascade="all, delete-orphan"
    )

    __mapper_args__ = {"eager_defaults": True}

    def __repr__(self) -> str:
        return f"<Scan {self.id} target={self.target} status={self.status}>"


from cybersec.database.models.user import User
from cybersec.database.models.scan_result import ScanResult
from cybersec.database.models.tool_result import ToolResult
from cybersec.database.models.report import Report
