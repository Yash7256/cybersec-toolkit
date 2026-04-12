"""
Base database models and mixins.
"""
import uuid
from sqlalchemy.orm import DeclarativeBase, mapped_column
from sqlalchemy import UUID, DateTime, func

class Base(DeclarativeBase):
    pass

class UUIDPrimaryKeyMixin:
    id = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

class TimestampMixin:
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at = mapped_column(DateTime(timezone=True), onupdate=func.now(), nullable=True)

# TODO: implement additional mixins
