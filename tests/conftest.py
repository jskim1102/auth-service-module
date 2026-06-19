"""Test bootstrap: load .env into the environment before any app module imports.

The app reads config from env (Settings) and the DB suite reads TEST_DATABASE_URL
directly (option A). Loading .env here lets the bare `pytest ...` Run command work
without the caller having to `source .env` first. Real env vars already set win.
"""
import os
from pathlib import Path

import pytest_asyncio
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

_ENV_FILE = Path(__file__).resolve().parent.parent / ".env"


def _load_env() -> None:
    if not _ENV_FILE.exists():
        return
    for line in _ENV_FILE.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip())


_load_env()


@pytest_asyncio.fixture(autouse=True)
async def _clean_db():
    """Central, metadata-driven test isolation against the persistent test postgres.

    Before each test, delete every table in reverse FK order
    (Base.metadata.sorted_tables, reversed). This auto-covers ALL registered
    models — current four plus any future user-FK table (e.g. phase6
    oauth_states / oauth_codes) — with zero per-file maintenance. Replaces the
    old bespoke per-file cleanup blocks (deprecated): adding a model no longer
    means editing N test fixtures (was the recurring FK-cleanup treadmill).

    autouse + function-scope: every test starts from a clean DB without having
    to reference the fixture. Skips silently if TEST_DATABASE_URL is unset (the
    non-DB unit tests, e.g. token tests, don't need it).
    """
    url = os.getenv("TEST_DATABASE_URL")
    if not url:
        yield
        return

    # Import models so every table is registered on Base.metadata before we read it.
    import app.models  # noqa: F401
    from app.db import Base

    engine = create_async_engine(url)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as session:
        for table in reversed(Base.metadata.sorted_tables):
            await session.execute(delete(table))
        await session.commit()
    await engine.dispose()
    yield
