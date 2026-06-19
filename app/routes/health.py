"""Health check — GET /auth/health (F11).

Liveness only: returns {status: ok} with no auth and no DB dependency, so an
orchestrator / smoke test can confirm the process is up.
"""
from fastapi import APIRouter

router = APIRouter(prefix="/auth", tags=["health"])


@router.get("/health")
async def health():
    return {"status": "ok"}
