"""Add NVD service lookup cache table

Revision ID: add_nvd_service_lookup_cache
Revises: add_scan_recovery
Create Date: 2026-06-28 13:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "add_nvd_service_lookup_cache"
down_revision: Union[str, None] = "add_scan_recovery"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "nvd_service_lookup_cache",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("cache_key", sa.String(64), nullable=False),
        sa.Column("service_name", sa.String(255), nullable=False),
        sa.Column("service_version", sa.String(255), nullable=False),
        sa.Column("results", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("fetched_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("expires_at", sa.TIMESTAMP(timezone=True), nullable=False),
    )
    op.create_index("ix_nvd_service_lookup_cache_cache_key", "nvd_service_lookup_cache", ["cache_key"], unique=True)
    op.create_index("ix_nvd_service_lookup_cache_expires_at", "nvd_service_lookup_cache", ["expires_at"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_nvd_service_lookup_cache_expires_at", table_name="nvd_service_lookup_cache")
    op.drop_index("ix_nvd_service_lookup_cache_cache_key", table_name="nvd_service_lookup_cache")
    op.drop_table("nvd_service_lookup_cache")
