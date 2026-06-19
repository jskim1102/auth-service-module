"""phase3.ckpt0 #17 — async db session reaches the live postgres.

The host-run suite uses TEST_DATABASE_URL (localhost:POSTGRES_PORT) directly —
it is test infrastructure, never part of the app's prod Settings (option A).
"""
import os

import pytest
from sqlalchemy import text

from app.db import make_engine, make_session_factory


def _test_db_url() -> str:
    url = os.getenv("TEST_DATABASE_URL")
    if not url:
        pytest.skip("TEST_DATABASE_URL not set")
    return url


@pytest.mark.asyncio
async def test_async_session_selects_one():
    engine = make_engine(_test_db_url())
    session_factory = make_session_factory(engine)
    async with session_factory() as session:
        result = await session.execute(text("SELECT 1"))
        assert result.scalar_one() == 1
    await engine.dispose()
