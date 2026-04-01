import uuid

from sqlalchemy import String, ForeignKey, JSON
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from cybersec.database.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class ToolResult(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "tool_results"
    __table_args__ = {"schema": None}

    scan_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    tool_name: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
    )
    target: Mapped[str] = mapped_column(String(255), nullable=False)
    result_data: Mapped[dict] = mapped_column(JSON, nullable=False)

    scan: Mapped["Scan"] = relationship("Scan", back_populates="tool_results")

    __mapper_args__ = {"eager_defaults": True}

    def __repr__(self) -> str:
        return f"<ToolResult {self.id} tool={self.tool_name} target={self.target}>"


from cybersec.database.models.scan import Scan
