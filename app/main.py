"""ASGI app assembly (phase8.ckpt2 — full).

Mounts every documented router and applies the phase8.ckpt1 security middleware
(rate-limit + CORS). Grew from the interim phase4-only form (EXTENDED, not
rewritten). Add new routers/middleware here.
"""
from fastapi import FastAPI

from app.routes.auth_find import router as auth_find_router
from app.routes.auth_local import router as auth_local_router
from app.routes.auth_reset import router as auth_reset_router
from app.routes.auth_token import router as auth_token_router
from app.routes.health import router as health_router
from app.routes.me import router as me_router
from app.routes.oauth import router as oauth_router
from app.routes.verify import router as verify_router
from app.security.middleware import apply_security

app = FastAPI(title="auth-service")

# Cross-cutting security (rate-limit + CORS) before the routers.
apply_security(app)

# Local auth (signup / login / logout / token refresh).
app.include_router(auth_local_router)
app.include_router(auth_token_router)
# Password reset + username (아이디) recovery.
app.include_router(auth_reset_router)
app.include_router(auth_find_router)
# SNS OAuth (authorize / callback / exchange).
app.include_router(oauth_router)
# User info + host verification surface.
app.include_router(me_router)
app.include_router(verify_router)
# Health.
app.include_router(health_router)
