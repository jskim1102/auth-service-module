"""User info — GET /auth/me (Bearer-protected, F9).

Verifies the Bearer access token (RS256, via tokens.verify_access) and returns the
user's profile plus the list of linked identity providers. Any missing / malformed
/ invalid / expired / tampered token → 401.
"""
from fastapi import APIRouter, Depends, Header, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_session
from app.models import AuthIdentity, User
from app.tokens import TokenError, verify_access

router = APIRouter(prefix="/auth", tags=["auth"])


def require_access_claims(authorization: str | None = Header(default=None)) -> dict:
    """FastAPI dependency: extract + verify the Bearer access token → claims or 401."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing bearer token")
    token = authorization[len("Bearer "):]
    try:
        return verify_access(token)
    except TokenError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid token")


@router.get("/me")
async def me(
    claims: dict = Depends(require_access_claims),
    session: AsyncSession = Depends(get_session),
):
    user_id = int(claims["sub"])
    user = (
        await session.execute(select(User).where(User.id == user_id))
    ).scalar_one_or_none()
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "user not found")

    providers = (
        await session.execute(
            select(AuthIdentity.provider).where(AuthIdentity.user_id == user_id)
        )
    ).scalars().all()

    return {
        "id": user.id,
        "email": user.email,
        "username": user.username,
        "identities": list(providers),
    }
