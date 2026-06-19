"""phase6.ckpt1 ← F8 — GET /auth/oauth/{provider}/authorize.

302 to the provider consent URL carrying a CSRF state and a PKCE S256 challenge;
the state + PKCE code_verifier are persisted (oauth_states) for the callback to
consume. Unsupported provider → 404. client_id comes from env.
"""
import urllib.parse as up

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker

from app.db import get_session, make_engine
from app.models import OAuthState
from app.routes.oauth import router
from sqlalchemy import select
from tests.test_migration import _async_test_url


@pytest_asyncio.fixture
async def factory():
    engine = make_engine(_async_test_url())
    sf = async_sessionmaker(engine, expire_on_commit=False)
    yield sf
    await engine.dispose()


@pytest_asyncio.fixture
async def client(factory):
    app = FastAPI()
    app.include_router(router)

    async def _override_session():
        async with factory() as s:
            yield s

    app.dependency_overrides[get_session] = _override_session
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.fixture(autouse=True)
def _provider_client_ids(monkeypatch):
    # Set non-empty ids so the URL-construction contract (client_id present) is testable.
    for p in ("NAVER", "KAKAO", "GOOGLE"):
        monkeypatch.setenv(f"{p}_CLIENT_ID", f"test-{p.lower()}-client-id")
    # Pin scopes deterministically (don't inherit live .env): google/naver have a
    # scope, KAKAO is EMPTY (omitted from the authorize URL — #27).
    monkeypatch.setenv("GOOGLE_SCOPE", "openid email profile")
    monkeypatch.setenv("NAVER_SCOPE", "name email")
    monkeypatch.setenv("KAKAO_SCOPE", "")


@pytest.mark.parametrize("provider", ["naver", "kakao", "google"])
@pytest.mark.asyncio
async def test_authorize_redirects_302_with_state_and_pkce(client, factory, provider):
    resp = await client.get(f"/auth/oauth/{provider}/authorize", follow_redirects=False)
    assert resp.status_code == 302
    location = resp.headers["location"]
    qs = up.parse_qs(up.urlparse(location).query)
    # CSRF state + PKCE S256 challenge present in the consent URL.
    assert qs.get("state"), "state missing from consent URL"
    assert qs.get("code_challenge"), "PKCE code_challenge missing"
    assert qs.get("code_challenge_method") == ["S256"]
    assert qs.get("response_type") == ["code"]
    assert qs.get("client_id"), "client_id missing"
    # scope present for providers that define one; kakao's is empty (asserted below).
    if provider != "kakao":
        assert qs.get("scope"), f"scope missing from {provider} consent URL"


@pytest.mark.asyncio
async def test_authorize_google_scope_includes_email(client, factory):
    resp = await client.get("/auth/oauth/google/authorize", follow_redirects=False)
    qs = up.parse_qs(up.urlparse(resp.headers["location"]).query)
    assert "email" in qs.get("scope", [""])[0]


@pytest.mark.asyncio
async def test_authorize_kakao_omits_scope_param(client, factory):
    # #27: empty KAKAO_SCOPE → the scope param is OMITTED entirely (not scope=) so
    # Kakao uses the app's default consent instead of rejecting invalid_scope.
    resp = await client.get("/auth/oauth/kakao/authorize", follow_redirects=False)
    assert resp.status_code == 302
    qs = up.parse_qs(up.urlparse(resp.headers["location"]).query)
    assert "scope" not in qs, "kakao authorize must omit scope when KAKAO_SCOPE is empty"
    # state + PKCE still present (the rest of the contract holds).
    assert qs.get("state") and qs.get("code_challenge")


@pytest.mark.asyncio
async def test_authorize_kakao_scope_override_included(client, factory, monkeypatch):
    # After Kakao email review, KAKAO_SCOPE=account_email → scope param appears.
    monkeypatch.setenv("KAKAO_SCOPE", "account_email")
    resp = await client.get("/auth/oauth/kakao/authorize", follow_redirects=False)
    qs = up.parse_qs(up.urlparse(resp.headers["location"]).query)
    assert qs.get("scope") == ["account_email"]


@pytest.mark.asyncio
async def test_authorize_persists_state_row(client, factory):
    resp = await client.get("/auth/oauth/google/authorize", follow_redirects=False)
    assert resp.status_code == 302
    async with factory() as s:
        rows = (await s.execute(select(OAuthState))).scalars().all()
    assert len(rows) == 1
    row = rows[0]
    assert row.provider == "google"
    assert row.code_verifier  # PKCE verifier stored for the callback
    assert row.used is False
    # state is stored HASHED, never the raw value that went to the provider.
    location = resp.headers["location"]
    raw_state = up.parse_qs(up.urlparse(location).query)["state"][0]
    assert row.state_hash != raw_state


@pytest.mark.asyncio
async def test_authorize_unknown_provider_404(client):
    resp = await client.get("/auth/oauth/facebook/authorize", follow_redirects=False)
    assert resp.status_code == 404


# --- fetch_userinfo normalization (REAL provider shapes → common form) ----------
# These pin the per-provider userinfo mapping. The original bug (returning raw
# json) hid because the callback mock returned a pre-normalized dict; testing the
# mapping directly against REAL shapes is the guard.
def test_normalize_google_userinfo():
    from app.oauth.providers import _normalize_userinfo

    out = _normalize_userinfo("google", {"sub": "g-1", "email": "a@e.com", "email_verified": True})
    assert out == {"provider_uid": "g-1", "email": "a@e.com", "email_verified": True}


def test_normalize_kakao_userinfo():
    from app.oauth.providers import _normalize_userinfo

    raw = {"id": 12345, "kakao_account": {"email": "k@e.com", "is_email_verified": True}}
    out = _normalize_userinfo("kakao", raw)
    assert out == {"provider_uid": "12345", "email": "k@e.com", "email_verified": True}


def test_normalize_naver_userinfo():
    from app.oauth.providers import _normalize_userinfo

    raw = {"response": {"id": "n-9", "email": "n@e.com"}}
    out = _normalize_userinfo("naver", raw)
    # Naver has no verified flag → a present email is treated as verified.
    assert out == {"provider_uid": "n-9", "email": "n@e.com", "email_verified": True}


def test_normalize_naver_error_in_200_raises_provider_error():
    # #20: naver auth-fail returns HTTP 200 + {resultcode!="00", no response}.
    from app.oauth.providers import ProviderError, _normalize_userinfo

    with pytest.raises(ProviderError):
        _normalize_userinfo("naver", {"resultcode": "024", "message": "cancelled"})


def test_normalize_missing_uid_raises_provider_error():
    # #20: a malformed payload (no uid) must raise, not KeyError → 500.
    from app.oauth.providers import ProviderError, _normalize_userinfo

    for provider, bad in [("google", {}), ("kakao", {}), ("naver", {"response": {}})]:
        with pytest.raises(ProviderError):
            _normalize_userinfo(provider, bad)


def test_email_verified_string_false_is_untrusted():
    # #20: bool("false")==True trap — explicit truthiness must reject the string.
    from app.oauth.providers import _normalize_userinfo

    out = _normalize_userinfo("google", {"sub": "g", "email": "a@e.com", "email_verified": "false"})
    assert out["email_verified"] is False
    out2 = _normalize_userinfo("google", {"sub": "g", "email": "a@e.com", "email_verified": "true"})
    assert out2["email_verified"] is True
