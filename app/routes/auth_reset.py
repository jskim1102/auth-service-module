"""Password reset routes (F7).

reset-request takes {identifier} = username OR email (login-style lookup). An
existing account WITH an email → mint a single-use, time-limited, sha256-hashed
token + send the raw token to that email + return 202 with a MASKED hint (local
first char + '*'×rest, full domain). An unknown identifier or an email-less SNS
id-only account → generic 202, NO hint. This is option-(a) (user-confirmed): a
minor account-enumeration tradeoff for UX, mitigated by the reset rate-limit
(F12) — it supersedes the earlier byte-identical-202 strict-enum standard.
reset (token → new argon2 password) is single-use: unused+unexpired → 204, else 400.
"""
import hashlib
import os
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import func, select, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_session
from app.email import send_reset_email
from app.models import PasswordReset, User
from app.refresh import _is_retryable  # canonical deadlock/serialization SQLSTATE check (#10)
from app.security.middleware import limiter, reset_limit
from app.security.hashing import hash_password

router = APIRouter(prefix="/auth/password", tags=["auth"])

# Reset tokens are short-lived; env-overridable for ops, sane default otherwise.
DEFAULT_RESET_TTL = 60 * 30  # 30 minutes

# Generic 202 body when there's nothing to send to (unknown identifier, or an
# email-less SNS id-only account). Option-(a), user-confirmed: a minor enumeration
# tradeoff for UX, mitigated by the reset rate-limit. (#31 — supersedes the old
# byte-identical-202 standard.)
_GENERIC_ACCEPTED = {"message": "If an account matches, a reset email has been sent."}


def _hash(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def _mask_email(email: str) -> str:
    """Mask the local part (first char + '*' per remaining char), keep the full domain.

    js.kim.deepi@gmail.com → j**********@gmail.com ; a@e.com → a@e.com (1-char local).
    """
    local, _, domain = email.partition("@")
    if not local:
        return email
    masked_local = local[0] + "*" * (len(local) - 1)
    return f"{masked_local}@{domain}"


def _reset_ttl() -> int:
    return int(os.environ.get("RESET_TTL", DEFAULT_RESET_TTL))


class ResetRequestIn(BaseModel):
    # identifier = username OR email (same lookup as login) — people who log in by
    # username may not recall the signup email (#31).
    identifier: str


class ResetIn(BaseModel):
    token: str
    new_password: str


@router.post("/reset-request", status_code=status.HTTP_202_ACCEPTED)
@limiter.limit(reset_limit)  # brute-force / spam guard (F12); request param required by slowapi
async def reset_request(
    request: Request, body: ResetRequestIn, session: AsyncSession = Depends(get_session)
):
    user = (
        await session.execute(
            select(User).where(
                (User.email == body.identifier) | (User.username == body.identifier)
            )
        )
    ).scalar_one_or_none()

    # Only a real account WITH an email gets a token + email + a masked hint. An
    # unknown identifier or an email-less SNS id-only account → generic 202, no hint
    # (option-a, user-confirmed). reset rate-limit mitigates the minor enum leak.
    if user is not None and user.email:
        raw_token = secrets.token_urlsafe(32)
        session.add(
            PasswordReset(
                token_hash=_hash(raw_token),
                user_id=user.id,
                expires_at=datetime.now(timezone.utc) + timedelta(seconds=_reset_ttl()),
                used=False,
            )
        )
        await session.commit()
        await send_reset_email(user.email, raw_token)
        return {"message": f"A reset email has been sent to {_mask_email(user.email)}."}

    return _GENERIC_ACCEPTED


async def _consume_token(session: AsyncSession, token_hash: str):
    """Atomically consume an unused, unexpired reset token. Returns user_id or None.

    Single conditional UPDATE (used=false AND not-expired → used=true RETURNING)
    so concurrent resets of one token cannot all pass a stale "used=false" read
    (the single-use TOCTOU, #15). Exactly one caller's UPDATE affects the row;
    every other caller gets zero rows = already-consumed/expired/unknown → 400.
    Deadlock/serialization (#10 family) → retry the idempotent consume once.
    """
    stmt = (
        update(PasswordReset)
        .where(
            PasswordReset.token_hash == token_hash,
            PasswordReset.used.is_(False),
            PasswordReset.expires_at > func.now(),
        )
        .values(used=True)
        .returning(PasswordReset.user_id)
    )
    for attempt in range(2):  # original try + one retry
        try:
            won = (await session.execute(stmt)).first()
            await session.commit()
            return won[0] if won is not None else None
        except DBAPIError as exc:
            await session.rollback()
            if attempt == 0 and _is_retryable(exc):
                continue
            raise


@router.post("/reset", status_code=status.HTTP_204_NO_CONTENT)
async def reset(body: ResetIn, session: AsyncSession = Depends(get_session)):
    # Atomic consume: only the winning caller gets a user_id and sets the password.
    user_id = await _consume_token(session, _hash(body.token))
    if user_id is None:
        # Unknown, already-used, or expired token → 400 (no password change).
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid or expired reset token")

    user = (
        await session.execute(select(User).where(User.id == user_id))
    ).scalar_one()
    user.password_hash = hash_password(body.new_password)
    await session.commit()

