import uuid

from sqlalchemy import String, Integer, Text, ForeignKey, JSON
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from cybersec.database.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class ScanResult(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "scan_results"
    __table_args__ = {"schema": None}

    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(10), nullable=True)
    state: Mapped[str | None] = mapped_column(String(20), nullable=True)
    service: Mapped[str | None] = mapped_column(String(100), nullable=True)
    version: Mapped[str | None] = mapped_column(String(255), nullable=True)
    cves: Mapped[list | None] = mapped_column(JSON, nullable=True)
    banner: Mapped[str | None] = mapped_column(Text, nullable=True)

    scan: Mapped["Scan"] = relationship("Scan", back_populates="results")

    __mapper_args__ = {"eager_defaults": True}

    def __repr__(self) -> str:
        return f"<ScanResult {self.id} port={self.port} state={self.state}>"


from cybersec.database.models.scan import Scan
