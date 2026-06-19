"""OAuth (SNS zero-friction) routes — authorize (F8).

authorize mints a CSRF state + PKCE (S256) pair, persists them hashed/time-limited
in oauth_states (for the callback to atomically consume), and 302-redirects to the
provider consent screen. Unsupported provider → 404. client_id comes from env.
"""
import base64
import hashlib
import os
import secrets
import urllib.parse as urlparse
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from sqlalchemy import func, select, text, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_session
from app.models import AuthIdentity, OAuthCode, OAuthState, User
from app.oauth.providers import ProviderError, exchange_code, fetch_userinfo, get_provider
from app.refresh import _is_retryable, issue_refresh
from app.routes.auth_local import _set_refresh_cookie
from app.security.redirects import is_allowed_redirect
from app.tokens import issue_access

router = APIRouter(prefix="/auth/oauth", tags=["oauth"])

DEFAULT_STATE_TTL = 60 * 10  # 10 minutes — authorize→callback window
DEFAULT_CODE_TTL = 60 * 2  # 2 minutes — callback→exchange window for the one-time code


def _hash(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def _state_ttl() -> int:
    return int(os.environ.get("OAUTH_STATE_TTL", DEFAULT_STATE_TTL))


def _code_ttl() -> int:
    return int(os.environ.get("OAUTH_CODE_TTL", DEFAULT_CODE_TTL))


async def _consume_state(session: AsyncSession, state_hash: str, provider: str):
    """Atomically consume a valid, unexpired, unused state for this provider.

    Single conditional UPDATE...RETURNING (no SELECT-then-UPDATE) so concurrent
    callbacks for one state can't both pass — exactly one wins. Returns the
    code_verifier, or None (unknown/used/expired/wrong-provider). Retry-once on
    deadlock/serialization (#10/#15 family).
    """
    stmt = (
        update(OAuthState)
        .where(
            OAuthState.state_hash == state_hash,
            OAuthState.provider == provider,
            OAuthState.used.is_(False),
            OAuthState.expires_at > func.now(),
        )
        .values(used=True)
        .returning(OAuthState.code_verifier)
    )
    for attempt in range(2):
        try:
            won = (await session.execute(stmt)).first()
            await session.commit()
            return won[0] if won is not None else None
        except DBAPIError as exc:
            await session.rollback()
            if attempt == 0 and _is_retryable(exc):
                continue
            raise


def _pkce_pair() -> tuple[str, str]:
    """Return (code_verifier, code_challenge) for PKCE S256."""
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).decode().rstrip("=")
    return verifier, challenge


def _callback_uri(request: Request, provider_name: str) -> str:
    # The provider redirects back to THIS service's callback. Prefer a deterministic
    # OAUTH_REDIRECT_BASE (must match what's registered with the provider) and fall
    # back to the request base (works behind the nginx proxy / in compose).
    base = (os.environ.get("OAUTH_REDIRECT_BASE") or str(request.base_url)).rstrip("/")
    return f"{base}/auth/oauth/{provider_name}/callback"


@router.get("/{provider}/authorize")
async def authorize(
    provider: str,
    request: Request,
    session: AsyncSession = Depends(get_session),
):
    prov = get_provider(provider)
    if prov is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "unsupported provider")

    raw_state = secrets.token_urlsafe(32)
    code_verifier, code_challenge = _pkce_pair()

    session.add(
        OAuthState(
            state_hash=_hash(raw_state),
            code_verifier=code_verifier,
            provider=provider,
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=_state_ttl()),
            used=False,
        )
    )
    await session.commit()

    params = {
        "response_type": "code",
        "client_id": prov.client_id,
        "redirect_uri": _callback_uri(request, provider),
        "state": raw_state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    # OMIT scope entirely when empty — an empty `scope=` makes Kakao reject
    # (invalid_scope); with no scope param Kakao uses the app's default consent and
    # returns the user id (no email) → id-only provisioning (#26/#27). Providers
    # that need a scope (google/naver) still send it.
    if prov.scope:
        params["scope"] = prov.scope
    consent_url = f"{prov.authorize_url}?{urlparse.urlencode(params)}"
    return RedirectResponse(consent_url, status_code=status.HTTP_302_FOUND)


def _success_redirect() -> str:
    """The host URL the one-time code is delivered to after a successful login.

    Derived from OAUTH_REDIRECT_BASE (default the demo host) → {base}/auth/callback,
    and MUST be whitelisted (ALLOWED_REDIRECT_URIS). The provider only sends back
    code+state, so the host return target is configured here, not taken from the
    request (a request-supplied target would be an open-redirect surface).
    """
    base = (os.environ.get("OAUTH_REDIRECT_BASE") or "").rstrip("/")
    return f"{base}/auth/callback"


@router.get("/{provider}/callback")
async def callback(
    provider: str,
    request: Request,
    state: str | None = None,
    code: str | None = None,
    error: str | None = None,
    error_description: str | None = None,
    session: AsyncSession = Depends(get_session),
):
    # Real providers redirect back with ONLY code + state (no redirect_uri) — so
    # the callback must NOT require it. On denial/cancel/invalid_scope a provider
    # instead redirects with ?error=&error_description=&state= and NO code — that
    # must be a clean 4xx, never a 422 schema error (hence code/state Optional).
    prov = get_provider(provider)
    if prov is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "unsupported provider")

    # Provider returned an error (or omitted code) → clean 400 with the provider's
    # own message. No state consumed, no token issued.
    if error or not code or not state:
        detail = error_description or error or "missing code/state in provider callback"
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"provider error: {detail}")

    # Whitelist the configured host success URL BEFORE any side effect — off-whitelist
    # (misconfig) → 400, no state burned, no token issued.
    success_url = _success_redirect()
    if not is_allowed_redirect(success_url):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "success redirect not allowed")

    # Atomically consume the state (CSRF + PKCE verifier). Unknown/used/expired → 400.
    code_verifier = await _consume_state(session, _hash(state), provider)
    if code_verifier is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid or expired state")

    # The redirect_uri sent to the provider's token endpoint MUST match the one
    # authorize used (OAuth requirement) — reconstruct it, don't take from the query.
    provider_redirect_uri = _callback_uri(request, provider)

    # Provider HTTP boundary — any error/malformed payload (incl. error-in-200)
    # maps to a clean 400, never a 500.
    try:
        token_set = await exchange_code(prov, code, code_verifier, provider_redirect_uri)
        access_token = token_set.get("access_token")
        if not access_token:
            raise ProviderError("provider token response missing access_token")
        profile = await fetch_userinfo(prov, access_token)
    except ProviderError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"provider error: {exc}")

    provider_uid = profile["provider_uid"]
    raw_email = profile.get("email")
    # Email is only trustworthy (for account linking) when the provider says it's
    # verified. An unverified or absent email is NOT used to find/link a user —
    # otherwise a forged provider email could hijack an existing account (#26).
    verified_email = raw_email if (raw_email and profile.get("email_verified")) else None

    identity = (
        await session.execute(
            select(AuthIdentity).where(
                AuthIdentity.provider == provider,
                AuthIdentity.provider_uid == provider_uid,
            )
        )
    ).scalar_one_or_none()

    if identity is not None:
        # Returning SNS user — identified by (provider, uid) alone, email-agnostic.
        user_id = identity.user_id
    elif verified_email is not None:
        # Verified email: link to the account that already owns it (local signup or
        # another provider) else create one with that email (account-linking decision).
        existing = (
            await session.execute(select(User).where(User.email == verified_email))
        ).scalar_one_or_none()
        if existing is not None:
            user_id = existing.id
        else:
            user = User(email=verified_email, username=None, password_hash=None)
            session.add(user)
            await session.flush()
            user_id = user.id
    else:
        # id-only provisioning (#26): no email or unverified (e.g. Kakao pre-review,
        # Apple Hide-My-Email). Create a user with email NULL, identified ONLY by
        # (provider, uid). No email-based linking — there's no trusted email to link.
        user = User(email=None, username=None, password_hash=None)
        session.add(user)
        await session.flush()
        user_id = user.id

    if identity is None:
        # Store the provider's email on the identity for info even if unverified
        # (the user record keeps NULL); NULL when the provider gave none.
        session.add(
            AuthIdentity(user_id=user_id, provider=provider, provider_uid=provider_uid, email=raw_email)
        )

    # Mint ONLY a short-lived one-time code (no tokens, no cookie here). The host
    # redirects through it and calls /auth/oauth/exchange, which is the SOLE issuer
    # of the access+refresh and the refresh cookie — so there's no orphan refresh
    # issued at callback that the exchange would then supersede. (#28 P1)
    one_time = secrets.token_urlsafe(32)
    session.add(
        OAuthCode(
            code_hash=_hash(one_time),
            user_id=user_id,
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=_code_ttl()),
            used=False,
        )
    )
    await session.commit()

    sep = "&" if urlparse.urlparse(success_url).query else "?"
    location = f"{success_url}{sep}{urlparse.urlencode({'code': one_time})}"
    return RedirectResponse(location, status_code=status.HTTP_302_FOUND)


class ExchangeIn(BaseModel):
    code: str


# Consume the one-time code AND fetch its user in ONE statement (#17). The earlier
# two-step (consume-commit, then a separate SELECT user) let the winner's SELECT
# transiently return 0 rows under concurrent pooled load → NoResultFound → 500,
# stranding the user with no token. A CTE that UPDATEs...RETURNING and JOINs users
# in the same statement returns the user atomically with the consume — the winner
# can never miss its own user.
_CONSUME_CODE_AND_USER = text(
    """
    WITH consumed AS (
        UPDATE oauth_codes SET used = true
        WHERE code_hash = :code_hash AND used = false AND expires_at > now()
        RETURNING user_id
    )
    SELECT u.id AS user_id, u.email AS email
    FROM users u JOIN consumed c ON u.id = c.user_id
    """
)


async def _consume_code_and_user(session: AsyncSession, code_hash: str):
    """Atomically consume the code and return (user_id, email), or None.

    Single statement (no SELECT-then-UPDATE, no second query that could miss the
    row). Retry-once on deadlock/serialization — same consume-once contract as
    state/reset/refresh.
    """
    for attempt in range(2):
        try:
            row = (await session.execute(_CONSUME_CODE_AND_USER, {"code_hash": code_hash})).first()
            await session.commit()
            return row  # (user_id, email) or None
        except DBAPIError as exc:
            await session.rollback()
            if attempt == 0 and _is_retryable(exc):
                continue
            raise


@router.post("/exchange")
async def exchange(
    body: ExchangeIn,
    response: Response,
    session: AsyncSession = Depends(get_session),
):
    row = await _consume_code_and_user(session, _hash(body.code))
    if row is None:
        # Genuinely invalid/expired/used (or, impossibly, a code with no user) → 400.
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid or expired code")

    user_id, email = row
    # issue_access reads .id and .email — a transient (unattached) User suffices.
    access = issue_access(User(id=user_id, email=email))
    refresh = await issue_refresh(session, user_id)
    _set_refresh_cookie(response, refresh)
    return {"access_token": access, "refresh_token": refresh}
