
from sqlalchemy import String, Boolean
from sqlalchemy.orm import Mapped, mapped_column, relationship

from cybersec.database.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class User(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "users"

    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_superuser: Mapped[bool] = mapped_column(Boolean, default=False)

    scans: Mapped[list["Scan"]] = relationship("Scan", back_populates="user", lazy="select")
    reports: Mapped[list["Report"]] = relationship("Report", back_populates="user", lazy="select")

    __mapper_args__ = {"eager_defaults": True}

    def __repr__(self) -> str:
        return f"<User {self.email}>"


from cybersec.database.models.scan import Scan
from cybersec.database.models.report import Report
