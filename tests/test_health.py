"""phase8.ckpt3 ← F11 — GET /auth/health.

Liveness probe: always {status: ok}, no auth, no DB dependency.
"""
import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from app.routes.health import router


@pytest_asyncio.fixture
async def client():
    app = FastAPI()
    app.include_router(router)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.mark.asyncio
async def test_health_returns_status_ok(client):
    resp = await client.get("/auth/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}
