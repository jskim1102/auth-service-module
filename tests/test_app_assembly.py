"""phase8.ckpt2 ← F12 — ASGI app assembly.

app/main.py mounts EVERY documented router and applies the phase8.ckpt1 security
middleware. Asserts each documented route path is registered on the app.
"""
from app.main import app

EXPECTED_ROUTES = {
    "/auth/signup",
    "/auth/login",
    "/auth/logout",
    "/auth/token/refresh",
    "/auth/password/reset-request",
    "/auth/password/reset",
    "/auth/oauth/{provider}/authorize",
    "/auth/oauth/{provider}/callback",
    "/auth/oauth/exchange",
    "/auth/me",
    "/auth/verify",
    "/.well-known/jwks.json",
    "/auth/health",
}


def test_all_documented_routes_registered():
    registered = {r.path for r in app.routes}
    missing = EXPECTED_ROUTES - registered
    assert not missing, f"unmounted routes: {missing}"


def test_security_middleware_applied():
    # CORS middleware + the slowapi limiter must be wired by app assembly.
    mw_classes = {m.cls.__name__ for m in app.user_middleware}
    assert "CORSMiddleware" in mw_classes
    assert getattr(app.state, "limiter", None) is not None
