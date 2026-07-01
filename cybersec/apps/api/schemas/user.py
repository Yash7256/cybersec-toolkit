"""
User pydantic schemas (post-Clerk migration).

UserCreate, Token, and TokenData have been removed — authentication is
now handled by Clerk and no local password registration exists.

UserOut is retained for API responses that return user info.
"""
from pydantic import BaseModel, ConfigDict
from uuid import UUID
from datetime import datetime
from typing import Optional


class UserOut(BaseModel):
    """Serialised representation of a local users row."""

    id: UUID
    email: Optional[str] = None          # nullable: Clerk users may not expose email
    clerk_user_id: Optional[str] = None  # Clerk identity token (user_XXXX)
    is_active: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
