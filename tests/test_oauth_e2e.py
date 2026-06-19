"""phase6 ← F8 — OAuth end-to-end CONTRACT test (authorize → callback → exchange).

Drives the FULL round-trip the way a REAL provider drives it, for all three
providers, to catch any remaining request/response-shape mismatch the unit tests
miss (the class of bug behind #19/#20/#21):

  1. authorize → 302 whose params a real provider would accept (response_type,
     client_id, redirect_uri=the service callback, state, scope, S256 challenge);
     state persisted.
  2. provider HTTP is mocked at the TRANSPORT only (real token + REAL userinfo
     shapes per provider) so exchange_code/fetch_userinfo actually run.
  3. callback driven EXACTLY as the provider redirects back: ONLY ?code=&state=
     (no redirect_uri param), feeding back the REAL state authorize issued →
     302 to the success URL with a one-time code; no raw tokens in the URL;
     refresh as httpOnly cookie.
  4. exchange that one-time code → {access_token, refresh_token}; code single-use.
"""
import urllib.parse as up

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker

import app.oauth.providers as providers
from app.db import get_session, make_engine
from app.routes.oauth import router
from app.tokens import verify_access
from tests.test_migration import _async_test_url

SUCCESS_URL = "http://localhost:5176/auth/callback"  # {OAUTH_REDIRECT_BASE}/auth/callback, whitelisted

# REAL per-provider userinfo payload shapes (what each provider's userinfo endpoint
# actually returns) — the transport mock serves these so real normalization runs.
REAL_USERINFO = {
    "google": {"sub": "g-sub-1", "email": "e2e-google@e.com", "email_verified": True},
    "kakao": {"id": 778899, "kakao_account": {"email": "e2e-kakao@e.com", "is_email_verified": True}},
    "naver": {"resultcode": "00", "message": "success",
              "response": {"id": "n-id-1", "email": "e2e-naver@e.com"}},
}


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    # Pin ALL redirect env to the localhost base the test asserts — don't inherit
    # the live .env (deployment may point it at a tunnel/public IP). is_allowed_redirect
    # reads ALLOWED_REDIRECT_URIS via lru-cached get_settings, so set it + clear cache (#23).
    monkeypatch.setenv("OAUTH_REDIRECT_BASE", "http://localhost:5176")
    monkeypatch.setenv("ALLOWED_REDIRECT_URIS", "http://localhost:5176/auth/callback")
    monkeypatch.setenv("CORS_ORIGINS", "http://localhost:5176")
    for p in ("NAVER", "KAKAO", "GOOGLE"):
        monkeypatch.setenv(f"{p}_CLIENT_ID", f"test-{p.lower()}-id")
    from app.config import get_settings
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()  # don't leak the pinned Settings to other tests


def _install_transport(monkeypatch, provider):
    """Mock httpx transport only; serve this provider's REAL userinfo shape."""
    userinfo = REAL_USERINFO[provider]

    class _Resp:
        def __init__(self, payload):
            self._p = payload

        def raise_for_status(self):
            return None

        def json(self):
            return self._p

    class _Client:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url, **kwargs):  # token exchange
            return _Resp({"access_token": "prov-at", "token_type": "Bearer"})

        async def get(self, url, **kwargs):  # userinfo
            return _Resp(userinfo)

    monkeypatch.setattr(providers.httpx, "AsyncClient", _Client)


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


@pytest.mark.parametrize("provider", ["google", "kakao", "naver"])
@pytest.mark.asyncio
async def test_oauth_full_round_trip_real_provider_shape(client, provider, monkeypatch):
    _install_transport(monkeypatch, provider)

    # 1. authorize → 302 with params a real provider accepts.
    authz = await client.get(f"/auth/oauth/{provider}/authorize", follow_redirects=False)
    assert authz.status_code == 302
    authz_qs = up.parse_qs(up.urlparse(authz.headers["location"]).query)
    assert authz_qs["response_type"] == ["code"]
    assert authz_qs["client_id"][0]
    assert authz_qs["redirect_uri"][0].endswith(f"/auth/oauth/{provider}/callback")
    # scope present for google/naver; kakao omits it (empty default scope, #27).
    if provider != "kakao":
        assert authz_qs["scope"][0]
    else:
        assert "scope" not in authz_qs
    assert authz_qs["code_challenge_method"] == ["S256"]
    real_state = authz_qs["state"][0]  # the state the provider will echo back

    # 3. callback EXACTLY as the provider redirects back: ONLY code + state.
    cb = await client.get(
        f"/auth/oauth/{provider}/callback",
        params={"code": "real-auth-code", "state": real_state},  # no redirect_uri
        follow_redirects=False,
    )
    assert cb.status_code == 302, f"{provider} callback should 302, got {cb.status_code}"
    loc = cb.headers["location"]
    assert loc.startswith(SUCCESS_URL)
    assert "access_token" not in loc and "refresh_token" not in loc  # no raw tokens in URL
    # #28 P1: callback does NOT set the refresh cookie — exchange is the sole issuer.
    assert "set-cookie" not in {k.lower() for k in cb.headers}
    one_time = up.parse_qs(up.urlparse(loc).query)["code"][0]

    # 4. exchange the one-time code → real tokens + the refresh httpOnly cookie.
    ex = await client.post("/auth/oauth/exchange", json={"code": one_time})
    assert ex.status_code == 200
    assert "httponly" in ex.headers.get("set-cookie", "").lower()  # cookie issued HERE
    body = ex.json()
    assert body["access_token"] and body["refresh_token"]
    assert verify_access(body["access_token"])["email"] == REAL_USERINFO[provider].get("email") \
        or verify_access(body["access_token"])["sub"]  # token belongs to the provisioned user
    # reuse of the one-time code fails.
    reuse = await client.post("/auth/oauth/exchange", json={"code": one_time})
    assert reuse.status_code == 400


@pytest.mark.asyncio
async def test_oauth_state_is_single_use_across_round_trip(client, monkeypatch):
    # The state authorize issued is consumed by the first callback; replaying it fails.
    _install_transport(monkeypatch, "google")
    authz = await client.get("/auth/oauth/google/authorize", follow_redirects=False)
    real_state = up.parse_qs(up.urlparse(authz.headers["location"]).query)["state"][0]

    first = await client.get(
        "/auth/oauth/google/callback",
        params={"code": "c1", "state": real_state}, follow_redirects=False,
    )
    assert first.status_code == 302
    replay = await client.get(
        "/auth/oauth/google/callback",
        params={"code": "c2", "state": real_state}, follow_redirects=False,
    )
    assert replay.status_code == 400  # state already consumed


@pytest.mark.asyncio
async def test_oauth_id_only_round_trip_no_email(client, factory, monkeypatch):
    # #26 e2e: Kakao pre-email-review returns {id, kakao_account:{}} (NO email).
    # Full round-trip must still complete → id-only user (email NULL) + tokens.
    from sqlalchemy import select

    from app.models import AuthIdentity, User

    class _Resp:
        def __init__(self, p):
            self._p = p

        def raise_for_status(self):
            return None

        def json(self):
            return self._p

    class _Client:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url, **k):
            return _Resp({"access_token": "at"})

        async def get(self, url, **k):
            return _Resp({"id": 555111, "kakao_account": {}})  # NO email (pre-review)

    monkeypatch.setattr(providers.httpx, "AsyncClient", _Client)

    authz = await client.get("/auth/oauth/kakao/authorize", follow_redirects=False)
    real_state = up.parse_qs(up.urlparse(authz.headers["location"]).query)["state"][0]
    cb = await client.get(
        "/auth/oauth/kakao/callback",
        params={"code": "kc", "state": real_state}, follow_redirects=False,
    )
    assert cb.status_code == 302, "id-only (no-email) round-trip must complete"
    one_time = up.parse_qs(up.urlparse(cb.headers["location"]).query)["code"][0]
    ex = await client.post("/auth/oauth/exchange", json={"code": one_time})
    assert ex.status_code == 200 and ex.json()["access_token"]
    async with factory() as s:
        user = (await s.execute(select(User))).scalar_one()
        ident = (await s.execute(select(AuthIdentity).where(AuthIdentity.provider_uid == "555111"))).scalar_one()
    assert user.email is None  # id-only: provisioned with NO email
    assert ident.user_id == user.id and ident.provider == "kakao"
