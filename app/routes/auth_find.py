"""아이디(username) 찾기 route — account recovery over the email channel.

Takes {email} and, when a user with that email AND a username exists, emails the
username to that address. ALWAYS returns an identical generic 202 (no account
enumeration): the username is delivered to the inbox, never echoed in the response.
Unknown emails and SNS id-only accounts (username NULL) send nothing. Email-only
recovery — the app has no phone/2nd channel — and since email is itself a login
identifier this is a convenience for username-preferring users. Rate-limited via
the shared reset spam guard (F12).
"""
from fastapi import APIRouter, Depends, Request, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_session
from app.email import send_username_email
from app.models import User
from app.security.middleware import limiter, reset_limit

router = APIRouter(prefix="/auth/username", tags=["auth"])

# Identical body in every case → the caller can't tell whether the email exists.
_GENERIC_ACCEPTED = {
    "message": "If an account with that email exists, its username has been emailed to it."
}


class FindUsernameIn(BaseModel):
    email: str


@router.post("/find", status_code=status.HTTP_202_ACCEPTED)
@limiter.limit(reset_limit)  # spam/enum guard (F12); request param required by slowapi
async def find_username(
    request: Request, body: FindUsernameIn, session: AsyncSession = Depends(get_session)
):
    user = (
        await session.execute(select(User).where(User.email == body.email))
    ).scalar_one_or_none()
    # Only a real account that actually HAS a username has something to recover.
    if user is not None and user.username:
        await send_username_email(user.email, user.username)
    return _GENERIC_ACCEPTED
