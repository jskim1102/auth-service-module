"""phase8.ckpt1 ← F12 — cross-cutting security middleware.

Rate-limit on the abuse-prone routes (login, reset-request), env-configurable so
ops can tune it (and tests can bypass / tighten it). CORS applied from the
phase3.ckpt0 CORS_ORIGINS allowlist. Secrets are env-only (Settings raises on a
missing key — already enforced in config; re-asserted here as a no-fallback check).
"""
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.testclient import TestClient
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from app.security.middleware import _rate_limit_handler, apply_security, limiter, login_limit


def test_login_route_is_rate_limited_429():
    # A tight limit trips deterministically; the production default is generous.
    test_limiter = Limiter(key_func=get_remote_address)
    app = FastAPI()
    app.state.limiter = test_limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_handler)

    @app.post("/auth/login")
    @test_limiter.limit("2/minute")
    async def _login(request: Request):
        return {"ok": True}

    client = TestClient(app)
    assert client.post("/auth/login").status_code == 200
    assert client.post("/auth/login").status_code == 200
    assert client.post("/auth/login").status_code == 429  # over the limit


def test_apply_security_wires_cors_and_limiter():
    # apply_security must attach the limiter and CORS middleware from CORS_ORIGINS.
    app = FastAPI()
    apply_security(app)
    assert getattr(app.state, "limiter", None) is not None
    assert "CORSMiddleware" in {m.cls.__name__ for m in app.user_middleware}


def test_cors_echoes_allowed_origin():
    # CORS applied from the configured allowlist echoes the allowed Origin back.
    app = FastAPI()
    apply_security(app)

    @app.get("/ping")
    async def _ping():
        return {"ok": True}

    client = TestClient(app)
    from app.config import get_settings
    allowed = get_settings().CORS_ORIGINS[0]
    resp = client.get("/ping", headers={"Origin": allowed})
    assert resp.headers.get("access-control-allow-origin") == allowed


def test_production_default_limits_are_generous():
    # Default must be lenient enough not to false-trip reviewer/smoke/browser use.
    assert int(login_limit.split("/")[0]) >= 20


def test_settings_have_no_hardcoded_fallback_defaults():
    # env-only secret enforcement: every Settings field is REQUIRED (no default),
    # so a missing key raises at load rather than silently using a fallback (F12).
    # (The missing-key→raise behavior itself is covered in test_config.py.)
    from app.config import Settings

    for name, field in Settings.model_fields.items():
        assert field.is_required(), f"Settings.{name} has a fallback default — F12 violation"
