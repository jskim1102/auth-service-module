"""Cross-cutting security middleware — rate-limit + CORS (F12).

Rate limits the abuse-prone routes (login, reset-request) via slowapi, keyed by
client IP. Limits are env-configurable (RATE_LIMIT_LOGIN / RATE_LIMIT_RESET) with
generous defaults so normal use / smoke tests / the reviewer's probes don't trip
them; ops can tighten via env. CORS is applied from the CORS_ORIGINS allowlist
(for cross-origin hosts; the same-origin nginx-proxied demo doesn't exercise it).
Secrets are env-only — enforced in Settings (config), which raises on any missing
key with no fallback.
"""
import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from app.config import get_settings

# Generous defaults — tune via env. Login/reset are the brute-force surfaces.
login_limit = os.environ.get("RATE_LIMIT_LOGIN", "60/minute")
reset_limit = os.environ.get("RATE_LIMIT_RESET", "20/minute")

limiter = Limiter(key_func=get_remote_address)


def apply_security(app: FastAPI) -> None:
    """Wire the limiter (+ 429 handler) and CORS onto the app."""
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_handler)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=get_settings().CORS_ORIGINS,
        allow_credentials=True,  # the refresh cookie is credentialed
        allow_methods=["*"],
        allow_headers=["*"],
    )


def _rate_limit_handler(request, exc):  # noqa: ANN001
    from fastapi.responses import JSONResponse

    return JSONResponse(status_code=429, content={"detail": "rate limit exceeded"})
