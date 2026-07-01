"""Add Clerk auth columns to users table

Revision ID: add_clerk_auth_columns
Revises: add_nvd_service_lookup_cache
Create Date: 2026-07-01 12:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "add_clerk_auth_columns"
down_revision: Union[str, None] = "add_nvd_service_lookup_cache"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add clerk_user_id column (nullable, no default) — Req 5.1
    op.add_column(
        "users",
        sa.Column("clerk_user_id", sa.String(255), nullable=True),
    )

    # Create unique constraint on clerk_user_id — Req 5.2
    op.create_unique_constraint(
        "uq_users_clerk_user_id",
        "users",
        ["clerk_user_id"],
    )

    # Create index on clerk_user_id for fast lookups — Req 5.3
    op.create_index(
        "ix_users_clerk_user_id",
        "users",
        ["clerk_user_id"],
        unique=False,
    )

    # Alter hashed_password to allow NULL (Clerk users have no local password) — Req 5.4
    op.alter_column(
        "users",
        "hashed_password",
        existing_type=sa.String(255),
        nullable=True,
    )

    # Alter email to allow NULL (Clerk users may not expose email) — Req 5.6
    op.alter_column(
        "users",
        "email",
        existing_type=sa.String(255),
        nullable=True,
    )


def downgrade() -> None:
    # Restore email to NOT NULL (only safe if no NULL emails exist) — Req 5.5
    op.alter_column(
        "users",
        "email",
        existing_type=sa.String(255),
        nullable=False,
    )

    # Restore hashed_password to NOT NULL (only safe if no Clerk-only rows exist) — Req 5.5
    op.alter_column(
        "users",
        "hashed_password",
        existing_type=sa.String(255),
        nullable=False,
    )

    # Drop index on clerk_user_id — Req 5.5
    op.drop_index("ix_users_clerk_user_id", table_name="users")

    # Drop unique constraint on clerk_user_id — Req 5.5
    op.drop_constraint("uq_users_clerk_user_id", "users", type_="unique")

    # Drop clerk_user_id column — Req 5.5
    op.drop_column("users", "clerk_user_id")
