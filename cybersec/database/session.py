import os
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine


def _get_database_url() -> str:
    return os.environ.get(
        "DATABASE_URL",
        "postgresql+asyncpg://postgres:postgres@localhost:5432/cybersec",
    )


def _get_pool_size() -> int:
    try:
        return int(os.environ.get("DATABASE_POOL_SIZE", "5"))
    except ValueError:
        return 5


def _get_max_overflow() -> int:
    try:
        return int(os.environ.get("DATABASE_MAX_OVERFLOW", "10"))
    except ValueError:
        return 10


def create_engine_and_session():
    url = _get_database_url()
    pool_size = _get_pool_size()
    max_overflow = _get_max_overflow()

    engine = create_async_engine(
        url,
        pool_size=pool_size,
        max_overflow=max_overflow,
        echo=False,
    )

    async_session = async_sessionmaker(
        engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    return engine, async_session


_async_engine = None
_async_session_maker = None


def get_engine():
    global _async_engine
    if _async_engine is None:
        _async_engine, _ = create_engine_and_session()
    return _async_engine


def get_session_maker():
    global _async_session_maker
    if _async_session_maker is None:
        _, _async_session_maker = create_engine_and_session()
    return _async_session_maker


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    session_maker = get_session_maker()
    async with session_maker() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
