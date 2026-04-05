"""
Database session management.
"""
from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from cybersec.config import settings
from cybersec.database.base import Base

engine = create_async_engine(
    settings.DATABASE_URL,
    pool_size=settings.DATABASE_POOL_SIZE,
    max_overflow=settings.DATABASE_MAX_OVERFLOW
)

async_session_maker = async_sessionmaker(
    engine,
    expire_on_commit=False
)

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with async_session_maker() as session:
        yield session

async def init_db():
    from cybersec.database.models import User, Scan, ScanResult, ToolResult, Report
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

# TODO: implement further session settings or utility funcs
