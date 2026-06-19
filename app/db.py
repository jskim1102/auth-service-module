"""Async database session wiring (SQLAlchemy + asyncpg).

The app builds its engine from Settings.DATABASE_URL (in-network compose URL).
make_engine/make_session_factory are factored out so the test suite can point a
separate engine at TEST_DATABASE_URL (host-facing) without touching prod config.
"""
from collections.abc import AsyncIterator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from app.config import get_settings


class Base(DeclarativeBase):
    """Declarative base — all ORM models and the Alembic migration target share this."""


def make_engine(database_url: str) -> AsyncEngine:
    return create_async_engine(database_url, pool_pre_ping=True)


def make_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


# App-level engine + factory bound to the prod contract URL.
_engine = make_engine(get_settings().DATABASE_URL)
_session_factory = make_session_factory(_engine)


async def get_session() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency: yield an async session bound to the app engine."""
    async with _session_factory() as session:
        yield session
