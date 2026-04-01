import uuid
import enum

from sqlalchemy import String, ForeignKey, Enum
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from cybersec.database.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class ReportFormat(str, enum.Enum):
    JSON = "json"
    CSV = "csv"
    PDF = "pdf"


class Report(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "reports"
    __table_args__ = {"schema": None}

    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    format: Mapped[ReportFormat] = mapped_column(
        Enum(ReportFormat, name="report_format_enum", create_constraint=True),
        nullable=False,
    )
    file_path: Mapped[str | None] = mapped_column(String(500), nullable=True)

    scan: Mapped["Scan"] = relationship("Scan", back_populates="reports")
    user: Mapped["User"] = relationship("User", back_populates="reports")

    __mapper_args__ = {"eager_defaults": True}

    def __repr__(self) -> str:
        return f"<Report {self.id} format={self.format}>"


from cybersec.database.models.scan import Scan
from cybersec.database.models.user import User
