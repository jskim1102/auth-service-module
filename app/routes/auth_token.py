"""Token refresh route — POST /auth/token/refresh (F5).

Reads the refresh from the request body OR the httpOnly cookie (body wins if
both are present, user-confirmed). Rotation is delegated to
app.refresh.rotate_refresh — the SINGLE atomic reuse-detection path (#22): one
call per request, no pre-SELECT, so concurrent rotations cannot bypass theft
detection. On success a new access token is issued and the rotated refresh is
returned in the body AND set as an httpOnly cookie (same value, both channels).
Expired / revoked / reused refresh → 401 (reuse also burns the chain in
rotate_refresh per F4).
"""
from fastapi import APIRouter, Cookie, Depends, HTTPException, Response, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_session
from app.models import RefreshToken, User
from app.refresh import RefreshError, _hash, rotate_refresh
from app.routes.auth_local import REFRESH_COOKIE, _set_refresh_cookie
from app.tokens import issue_access

router = APIRouter(prefix="/auth", tags=["auth"])


class RefreshIn(BaseModel):
    refresh_token: str | None = None


@router.post("/token/refresh")
async def token_refresh(
    response: Response,
    body: RefreshIn,
    refresh_cookie: str | None = Cookie(default=None, alias=REFRESH_COOKIE),
    session: AsyncSession = Depends(get_session),
):
    # Body wins over cookie (user-confirmed). Pick ONE source — never try both.
    presented = body.refresh_token or refresh_cookie
    if not presented:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "no refresh token")

    try:
        new_refresh = await rotate_refresh(session, presented)
    except RefreshError:
        # Expired, unknown, or reused (chain already burned inside rotate_refresh).
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid refresh token")

    # Resolve the owning user from the freshly-minted row (no rotate signature change).
    user = (
        await session.execute(
            select(User)
            .join(RefreshToken, RefreshToken.user_id == User.id)
            .where(RefreshToken.token_hash == _hash(new_refresh))
        )
    ).scalar_one()

    access = issue_access(user)
    _set_refresh_cookie(response, new_refresh)
    return {"access_token": access, "refresh_token": new_refresh}
