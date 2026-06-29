"""Add NVD CVE cache table

Revision ID: 2026_4_24_1645
Revises: 2026_4_2_1858-7e75a30307de_initial
Create Date: 2026-04-24 16:45:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '2026_4_24_1645'
down_revision: Union[str, None] = '7e75a30307de'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create nvd_cve_cache table."""
    op.create_table('nvd_cve_cache',
        sa.Column('cve_id', sa.String(length=20), nullable=False),
        sa.Column('data', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('fetched_at', sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column('expires_at', sa.TIMESTAMP(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('cve_id')
    )
    op.create_index(op.f('ix_nvd_cve_cache_expires_at'), 'nvd_cve_cache', ['expires_at'], unique=False)


def downgrade() -> None:
    """Drop nvd_cve_cache table."""
    op.drop_index(op.f('ix_nvd_cve_cache_expires_at'), table_name='nvd_cve_cache')
    op.drop_table('nvd_cve_cache')
