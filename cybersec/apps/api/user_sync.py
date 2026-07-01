"""
User synchronization module for Clerk authentication.

Maintains a local `users` row for every Clerk-authenticated user who hits the API.
Implements a three-path upsert strategy:
  1. Fast path — clerk_user_id already exists → return immediately
  2. Legacy migration — email match on a legacy row → link in-place, preserve FKs
  3. New user — insert fresh row with hashed_password=NULL
"""
import logging

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from cybersec.database.models import User

logger = logging.getLogger(__name__)


async def sync_clerk_user(
    clerk_user_id: str,
    email: str | None,
    db: AsyncSession,
) -> User:
    """Upsert a local users row for the given Clerk identity.

    Args:
        clerk_user_id: The Clerk user identifier (format: user_XXXX).
        email: The email address from the Clerk JWT payload, or None if not exposed.
        db: An open async SQLAlchemy session.

    Returns:
        The existing or newly-created User ORM object.
    """
    # -------------------------------------------------------------------------
    # Path 1 — Fast path: row already exists with this clerk_user_id
    # -------------------------------------------------------------------------
    result = await db.execute(
        select(User).where(User.clerk_user_id == clerk_user_id)
    )
    existing_user = result.scalar_one_or_none()

    if existing_user is not None:
        logger.debug(
            "sync_clerk_user: fast path — clerk_user_id=%s already synced (users.id=%s)",
            clerk_user_id,
            existing_user.id,
        )
        return existing_user

    # -------------------------------------------------------------------------
    # Path 2 — Legacy migration: find a pre-Clerk row by email and link it
    # -------------------------------------------------------------------------
    if email is not None:
        legacy_result = await db.execute(
            select(User).where(
                User.email == email,
                User.clerk_user_id.is_(None),
            )
        )
        legacy_user = legacy_result.scalar_one_or_none()

        if legacy_user is not None:
            logger.debug(
                "sync_clerk_user: legacy migration — linking email=%s to clerk_user_id=%s "
                "(users.id=%s preserved, all FK references intact)",
                email,
                clerk_user_id,
                legacy_user.id,
            )
            legacy_user.clerk_user_id = clerk_user_id
            legacy_user.hashed_password = None  # password no longer needed
            await db.commit()
            return legacy_user

    # -------------------------------------------------------------------------
    # Path 3 — New Clerk user: insert a fresh row
    # -------------------------------------------------------------------------
    logger.debug(
        "sync_clerk_user: new user — creating row for clerk_user_id=%s email=%s",
        clerk_user_id,
        email,
    )
    new_user = User(
        clerk_user_id=clerk_user_id,
        email=email,
        hashed_password=None,
        is_active=True,
    )
    db.add(new_user)

    try:
        await db.commit()
        await db.refresh(new_user)
        return new_user
    except IntegrityError:
        # Race condition: another concurrent request created the same row first.
        # Roll back and re-query to return the winner's row.
        await db.rollback()
        logger.debug(
            "sync_clerk_user: IntegrityError on insert for clerk_user_id=%s "
            "— concurrent upsert detected, re-querying",
            clerk_user_id,
        )
        result = await db.execute(
            select(User).where(User.clerk_user_id == clerk_user_id)
        )
        return result.scalar_one()
