"""phase7.ckpt2 ← F10 — JWKS + verify (host token-verification surface).

GET /.well-known/jwks.json → RS256 PUBLIC JWK set (kty/use/alg/n/e/kid), with NO
private key components ever exposed. GET /auth/verify validates a presented access
token and returns its claims, else 401. The JWKS kid MUST match the kid stamped in
the access-token header so a host can select the right key.
"""
import jwt
import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from app.models import User
from app.routes.verify import router
from app.tokens import issue_access

PRIVATE_JWK_COMPONENTS = {"d", "p", "q", "dp", "dq", "qi"}


@pytest_asyncio.fixture
async def client():
    app = FastAPI()
    app.include_router(router)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


def _token():
    return issue_access(User(id=1, email="v@e.com"))


@pytest.mark.asyncio
async def test_jwks_returns_rs256_public_keyset(client):
    resp = await client.get("/.well-known/jwks.json")
    assert resp.status_code == 200
    body = resp.json()
    assert "keys" in body and len(body["keys"]) >= 1
    jwk = body["keys"][0]
    assert jwk["kty"] == "RSA"
    assert jwk["use"] == "sig"
    assert jwk["alg"] == "RS256"
    assert jwk["n"] and jwk["e"] and jwk["kid"]


@pytest.mark.asyncio
async def test_jwks_never_exposes_private_key(client):
    resp = await client.get("/.well-known/jwks.json")
    jwk = resp.json()["keys"][0]
    leaked = PRIVATE_JWK_COMPONENTS & set(jwk.keys())
    assert leaked == set(), f"JWKS leaked private key components: {leaked}"


@pytest.mark.asyncio
async def test_jwks_kid_matches_token_header(client):
    resp = await client.get("/.well-known/jwks.json")
    jwks_kid = resp.json()["keys"][0]["kid"]
    header = jwt.get_unverified_header(_token())
    assert header.get("kid") == jwks_kid


@pytest.mark.asyncio
async def test_verify_valid_token_returns_claims(client):
    resp = await client.get("/auth/verify", headers={"Authorization": f"Bearer {_token()}"})
    assert resp.status_code == 200
    claims = resp.json()
    assert claims["sub"] == "1"
    assert claims["email"] == "v@e.com"


@pytest.mark.asyncio
async def test_verify_tampered_token_401(client):
    token = _token()
    tampered = token[:-3] + ("aaa" if not token.endswith("aaa") else "bbb")
    resp = await client.get("/auth/verify", headers={"Authorization": f"Bearer {tampered}"})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_verify_missing_token_401(client):
    resp = await client.get("/auth/verify")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_verify_query_token_no_longer_accepted(client):
    # #29: the ?token= channel was removed — a valid token in the query is ignored
    # (no header) → 401, so tokens can't leak via URL / access log / Referer.
    resp = await client.get("/auth/verify", params={"token": _token()})
    assert resp.status_code == 401
