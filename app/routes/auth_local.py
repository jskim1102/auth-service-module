"""Local auth routes — signup (F2), login (F3).

POST /auth/signup creates a local-provider account: argon2-hashed password on
users, plus an auth_identities(provider="local") row. Duplicate email or
username → 409 (pre-checked, and the DB unique constraints are the backstop).

POST /auth/login verifies the password for an email-or-username identifier and
issues an access token plus a refresh token. The refresh is returned in the body
AND set as an httpOnly cookie — the SAME value in both channels (user-confirmed).
"""
import os

from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_session
from app.models import AuthIdentity, User
from app.refresh import issue_refresh, revoke_refresh
from app.security.hashing import hash_password, verify_password
from app.security.middleware import limiter, login_limit
from app.tokens import issue_access

router = APIRouter(prefix="/auth", tags=["auth"])

REFRESH_COOKIE = "refresh_token"


def _cookie_secure() -> bool:
    # Secure flag on the refresh cookie — default TRUE (HTTPS-only). Set
    # COOKIE_SECURE=false ONLY for local http dev. (#28 P1)
    return os.environ.get("COOKIE_SECURE", "true").lower() != "false"


def _set_refresh_cookie(response: Response, raw_refresh: str) -> None:
    """Set the refresh token as an httpOnly cookie (same value the body carries)."""
    response.set_cookie(
        key=REFRESH_COOKIE,
        value=raw_refresh,
        httponly=True,
        secure=_cookie_secure(),
        samesite="lax",
        path="/",
    )


class SignupIn(BaseModel):
    # Input validation (#29): non-empty username, valid email, password >= 8 chars.
    username: str = Field(min_length=3, max_length=64)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class LoginIn(BaseModel):
    # identifier is username OR email — kept a plain non-empty str.
    identifier: str = Field(min_length=1)
    password: str = Field(min_length=1)


class LogoutIn(BaseModel):
    # Optional: the refresh normally rides in the httpOnly cookie; body is a fallback.
    refresh_token: str | None = None


@router.post("/signup", status_code=status.HTTP_201_CREATED)
async def signup(body: SignupIn, session: AsyncSession = Depends(get_session)):
    existing = (
        await session.execute(
            select(User).where(
                (User.email == body.email) | (User.username == body.username)
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "email or username already registered")

    user = User(
        email=body.email,
        username=body.username,
        password_hash=hash_password(body.password),
    )
    session.add(user)
    try:
        await session.flush()  # assign user.id without ending the transaction
        session.add(
            AuthIdentity(user_id=user.id, provider="local", provider_uid=body.email)
        )
        await session.commit()
    except IntegrityError:
        # Lost a race against a concurrent signup with the same email/username.
        await session.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, "email or username already registered")

    return {"id": user.id, "email": user.email, "username": user.username}


@router.post("/login")
@limiter.limit(login_limit)  # brute-force guard (F12); request param required by slowapi
async def login(
    request: Request,
    body: LoginIn,
    response: Response,
    session: AsyncSession = Depends(get_session),
):
    user = (
        await session.execute(
            select(User).where(
                (User.email == body.identifier) | (User.username == body.identifier)
            )
        )
    ).scalar_one_or_none()
    # Same 401 for unknown user and bad password — no account enumeration.
    if user is None or user.password_hash is None or not verify_password(
        body.password, user.password_hash
    ):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials")

    access = issue_access(user)
    refresh = await issue_refresh(session, user.id)
    _set_refresh_cookie(response, refresh)
    return {"access_token": access, "refresh_token": refresh}


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    response: Response,
    body: LogoutIn = LogoutIn(),
    refresh_cookie: str | None = Cookie(default=None, alias=REFRESH_COOKIE),
    session: AsyncSession = Depends(get_session),
):
    # Read the refresh from the httpOnly cookie (how the browser holds it) or the
    # body fallback. Idempotent single-row revoke — never a chain burn (F6). Unknown
    # / already-revoked / absent → still 204 (no enumeration). (#28 P1)
    presented = refresh_cookie or body.refresh_token
    if presented:
        await revoke_refresh(session, presented)
    response.delete_cookie(REFRESH_COOKIE, path="/")
