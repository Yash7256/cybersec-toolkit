"""
FastAPI dependencies (get_db, get_current_user).
"""
from typing import Optional

from fastapi import Depends, HTTPException, status, Header
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from cybersec.database.session import get_db
from cybersec.database.models import User
from cybersec.api.auth import verify_token, oauth2_scheme

async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db)
) -> User:
    token_data = verify_token(token)
    
    result = await db.execute(select(User).where(User.id == token_data.user_id))
    user = result.scalars().first()
    
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return user


async def get_optional_user(
    authorization: Optional[str] = Header(default=None),
    db: AsyncSession = Depends(get_db)
) -> Optional[User]:
    if not authorization:
        return None
        
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
        
    token = parts[1]
    
    try:
        token_data = verify_token(token)
    except HTTPException:
        return None

    try:
        result = await db.execute(select(User).where(User.id == token_data.user_id))
        user = result.scalars().first()
        return user
    except Exception:
        # If DB is unavailable, treat as anonymous instead of failing the request.
        return None
