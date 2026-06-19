"""Host token-verification surface — JWKS + verify (F10).

/.well-known/jwks.json publishes the RS256 PUBLIC key set (kty/use/alg/n/e/kid)
so a host can verify access tokens itself without ever holding the private key.
/auth/verify validates an access token presented as Authorization: Bearer (header
ONLY — no query param, so tokens never reach URLs/logs) and returns its claims,
else 401. The JWKS kid matches the access-token header kid.
"""
from fastapi import APIRouter, Header, HTTPException, status

from app.tokens import TokenError, public_jwk, verify_access

router = APIRouter(tags=["auth"])


@router.get("/.well-known/jwks.json")
async def jwks():
    # public_jwk() is public-only (no d/p/q/...) — single source shared with the
    # token header kid, so host key-selection always matches.
    return {"keys": [public_jwk()]}


@router.get("/auth/verify")
async def verify(
    authorization: str | None = Header(default=None),
):
    # Authorization: Bearer ONLY — the ?token= query channel was dropped (#29) so a
    # token never lands in a URL / access log / Referer header.
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing bearer token")
    presented = authorization[len("Bearer "):]
    try:
        return verify_access(presented)
    except TokenError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid token")
