"""Add user tier and per-tool usage tracking

Replaces the earlier draft that added daily_usage_count + usage_reset_date.
Instead we store a single JSONB column `tool_usage` whose schema is:

    { "<tool_name>": { "count": <int>, "date": "<YYYY-MM-DD>" }, ... }

This lets each tool have its own independent 5-uses-per-day counter.

Revision ID: add_user_tier_and_usage
Revises: add_clerk_auth_columns
Create Date: 2026-06-30 00:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

# revision identifiers, used by Alembic.
revision: str = "add_user_tier_and_usage"
down_revision: Union[str, None] = "add_clerk_auth_columns"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create the user_tier_enum type (guard against pre-existing type)
    op.execute("""
        DO $$ BEGIN
            CREATE TYPE user_tier_enum AS ENUM ('free', 'paid');
        EXCEPTION WHEN duplicate_object THEN null;
        END $$;
    """)

    # Add tier column — all existing users default to 'free'
    op.add_column(
        "users",
        sa.Column(
            "tier",
            sa.Enum("free", "paid", name="user_tier_enum"),
            nullable=False,
            server_default="free",
        ),
    )

    # Add tool_usage JSONB — starts as empty dict for all users
    # Schema: { "<tool_name>": { "count": int, "date": "YYYY-MM-DD" }, ... }
    op.add_column(
        "users",
        sa.Column(
            "tool_usage",
            JSONB(),
            nullable=False,
            server_default="{}",
        ),
    )


def downgrade() -> None:
    op.drop_column("users", "tool_usage")
    op.drop_column("users", "tier")
    op.execute("""
        DO $$ BEGIN
            DROP TYPE user_tier_enum;
        EXCEPTION WHEN undefined_object THEN null;
        END $$;
    """)
