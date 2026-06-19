"""phase3.ckpt1 #19 — Alembic migration builds the four tables on live postgres (F1).

Runs `alembic upgrade head` against TEST_DATABASE_URL (host-facing, option A) then
inspects the real database for the tables and their constraints. The migration is
brought to a clean base first so the test is repeatable against the persistent DB.
Inspection uses the async engine via run_sync — the project ships only asyncpg.
"""
import os
import subprocess
import sys

import pytest
from sqlalchemy import inspect
from sqlalchemy.ext.asyncio import create_async_engine


def _async_test_url() -> str:
    url = os.getenv("TEST_DATABASE_URL")
    if not url:
        pytest.skip("TEST_DATABASE_URL not set")
    return url


def _alembic(*args: str):
    # conftest loaded .env into os.environ; pass it through so env.py sees TEST_DATABASE_URL.
    # Invoke via the current interpreter (sys.executable -m alembic) so the test
    # passes even when the venv isn't activated on PATH (#29).
    return subprocess.run(
        [sys.executable, "-m", "alembic", *args],
        capture_output=True,
        text=True,
        cwd=os.path.dirname(os.path.dirname(__file__)),
        env=os.environ,
    )


async def _inspect(fn):
    """Run a sync sqlalchemy inspect callback against the live DB via the async engine."""
    engine = create_async_engine(_async_test_url())
    async with engine.connect() as conn:
        result = await conn.run_sync(lambda sync_conn: fn(inspect(sync_conn)))
    await engine.dispose()
    return result


@pytest.fixture(scope="module", autouse=True)
def migrated_db():
    # Clean slate then upgrade — repeatable on the persistent test postgres.
    down = _alembic("downgrade", "base")
    assert down.returncode == 0, down.stderr
    up = _alembic("upgrade", "head")
    assert up.returncode == 0, up.stderr
    yield


@pytest.mark.asyncio
async def test_all_four_tables_created():
    tables = set(await _inspect(lambda insp: insp.get_table_names()))
    assert {"users", "auth_identities", "refresh_tokens", "password_resets"} <= tables


@pytest.mark.asyncio
async def test_users_unique_constraints():
    unique_cols = await _inspect(
        lambda insp: {tuple(uc["column_names"]) for uc in insp.get_unique_constraints("users")}
    )
    index_cols = await _inspect(
        lambda insp: {tuple(ix["column_names"]) for ix in insp.get_indexes("users") if ix["unique"]}
    )
    all_unique = unique_cols | index_cols
    assert ("email",) in all_unique
    assert ("username",) in all_unique


@pytest.mark.asyncio
async def test_auth_identities_composite_unique_and_fk():
    unique_cols = await _inspect(
        lambda insp: {
            tuple(uc["column_names"]) for uc in insp.get_unique_constraints("auth_identities")
        }
    )
    assert ("provider", "provider_uid") in unique_cols
    fk_tables = await _inspect(
        lambda insp: {fk["referred_table"] for fk in insp.get_foreign_keys("auth_identities")}
    )
    assert "users" in fk_tables


@pytest.mark.asyncio
async def test_refresh_tokens_has_chain_id_and_fk():
    cols = await _inspect(lambda insp: {c["name"] for c in insp.get_columns("refresh_tokens")})
    assert "chain_id" in cols
    fk_tables = await _inspect(
        lambda insp: {fk["referred_table"] for fk in insp.get_foreign_keys("refresh_tokens")}
    )
    assert "users" in fk_tables


@pytest.mark.asyncio
async def test_password_resets_fk():
    fk_tables = await _inspect(
        lambda insp: {fk["referred_table"] for fk in insp.get_foreign_keys("password_resets")}
    )
    assert "users" in fk_tables
