"""add scan recovery fields

Revision ID: add_scan_recovery
Revises: add_nvd_cve_cache
Create Date: 2026-05-15 12:00:00.000000
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "add_scan_recovery"
down_revision: Union[str, None] = "2026_4_24_1645"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("heartbeat_at", sa.TIMESTAMP(timezone=True), nullable=True))
    op.add_column("scans", sa.Column("worker_id", sa.String(100), nullable=True))
    op.add_column("scans", sa.Column("progress_pct", sa.Integer(), server_default="0"))
    op.add_column("scans", sa.Column("error_message", sa.Text(), nullable=True))

    op.create_table(
        "worker_heartbeats",
        sa.Column("worker_id", sa.String(100), primary_key=True),
        sa.Column("hostname", sa.String(255), nullable=True),
        sa.Column("pid", sa.Integer(), nullable=True),
        sa.Column("active_scans", sa.Integer(), server_default="0"),
        sa.Column("last_heartbeat", sa.TIMESTAMP(timezone=True), nullable=False),
    )

    op.execute("ALTER TYPE scan_status_enum ADD VALUE IF NOT EXISTS 'cancelled'")
    op.execute("ALTER TYPE scan_status_enum ADD VALUE IF NOT EXISTS 'timed_out'")


def downgrade() -> None:
    op.drop_table("worker_heartbeats")
    op.drop_column("scans", "heartbeat_at")
    op.drop_column("scans", "worker_id")
    op.drop_column("scans", "progress_pct")
    op.drop_column("scans", "error_message")
