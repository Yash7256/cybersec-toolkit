"""
Database session management.
"""
from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from cybersec.config import settings
from cybersec.database.base import Base

# Create engine with connection pool settings for Supabase
engine = create_async_engine(
    settings.DATABASE_URL,
    connect_args={"ssl": "require"},
    pool_size=1,  # Smaller pool for Supabase
    max_overflow=2,
    pool_pre_ping=True,  # Verify connections before use
    pool_recycle=300,  # Recycle connections every 5 minutes
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
