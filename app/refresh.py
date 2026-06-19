"""Refresh tokens — issue, rotate, reuse-detection (F4, security core).

Only the sha256 hash of a token is persisted (plaintext is returned once to the
caller and never stored). Rotation revokes the presented token and issues a new
one in the same chain. Presenting an already-revoked token is treated as theft:
the entire chain (chain_id family) is revoked and the call raises (CTO option A —
other chains/devices are left untouched).
"""
import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import RefreshToken

DEFAULT_REFRESH_TTL = 60 * 60 * 24 * 14  # 14 days

# Postgres SQLSTATEs that mean "the txn lost a lock race, retry is safe":
# 40P01 = deadlock_detected, 40001 = serialization_failure.
_RETRYABLE_SQLSTATES = {"40P01", "40001"}


class RefreshError(Exception):
    """Raised on expired, unknown, or reused (revoked) refresh tokens."""


def _hash(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _is_retryable(exc: DBAPIError) -> bool:
    return getattr(getattr(exc, "orig", None), "sqlstate", None) in _RETRYABLE_SQLSTATES


async def _revoke_chain(session: AsyncSession, chain_id) -> None:
    """Burn the whole rotation family — idempotent, deadlock-resilient (#10).

    The chain-wide `UPDATE ... WHERE chain_id` touches multiple rows, so two
    concurrent reuse-burns on the same chain can acquire row locks in different
    orders across separate postgres backends and deadlock (40P01). Because the
    burn is idempotent (re-revoking already-revoked rows is a no-op), a deadlock
    victim can simply roll back and retry once. The caller still raises
    RefreshError afterwards either way, so reuse always maps to 401 — never 500.
    """
    for attempt in range(2):  # original try + one retry
        try:
            await session.execute(
                update(RefreshToken)
                .where(RefreshToken.chain_id == chain_id)
                .values(revoked=True)
            )
            await session.commit()
            return
        except DBAPIError as exc:
            await session.rollback()
            if attempt == 0 and _is_retryable(exc):
                continue  # lost a lock race — retry the idempotent burn once
            # Persistent failure: the winning txn has (or will) revoke the chain,
            # so swallow and let the caller raise RefreshError → 401 (never 500).
            return


async def issue_refresh(
    session: AsyncSession,
    user_id: int,
    *,
    chain_id=None,
    ttl_seconds: int = DEFAULT_REFRESH_TTL,
) -> str:
    """Mint a refresh token, store its hash, return the plaintext (once)."""
    raw = secrets.token_urlsafe(32)
    row = RefreshToken(
        token_hash=_hash(raw),
        user_id=user_id,
        chain_id=chain_id or uuid.uuid4(),
        expires_at=_now() + timedelta(seconds=ttl_seconds),
        revoked=False,
    )
    session.add(row)
    await session.commit()
    return raw


async def rotate_refresh(session: AsyncSession, raw_token: str) -> str:
    """Validate + rotate atomically. Reuse of a revoked token burns the whole chain.

    The check-and-revoke is a SINGLE conditional UPDATE so concurrent rotations of
    one token cannot all pass a stale "not revoked" read (the TOCTOU race). Exactly
    one caller's UPDATE affects the row; every other caller gets zero rows and is
    treated as reuse/theft — the whole chain is revoked and the call raises.
    """
    token_hash = _hash(raw_token)
    won = (
        await session.execute(
            update(RefreshToken)
            .where(RefreshToken.token_hash == token_hash, RefreshToken.revoked.is_(False))
            .values(revoked=True)
            .returning(RefreshToken.chain_id, RefreshToken.user_id, RefreshToken.expires_at)
        )
    ).first()
    await session.commit()

    if won is None:
        # Zero rows: either the token never existed, or it was already revoked.
        existing = (
            await session.execute(
                select(RefreshToken.chain_id).where(RefreshToken.token_hash == token_hash)
            )
        ).first()
        if existing is not None:
            # Token exists but was already revoked → reuse/theft: burn the chain.
            await _revoke_chain(session, existing.chain_id)
            raise RefreshError("refresh token reuse detected — chain revoked")
        raise RefreshError("unknown refresh token")

    chain_id, user_id, expires_at = won
    if expires_at <= _now():
        raise RefreshError("refresh token expired")

    # Winner: mint the successor in the same chain.
    return await issue_refresh(session, user_id, chain_id=chain_id)


async def revoke_refresh(session: AsyncSession, raw_token: str) -> None:
    """Logout revoke — idempotent, single-row, NEVER a chain burn (F6).

    Plain UPDATE of ONLY the presented token's row. Deliberately has NO
    `revoked=false` guard and NO chain revocation: logging out (or double
    logging-out, or presenting an unknown token) must not touch the rest of the
    rotation family. Chain burning belongs solely to rotate_refresh on reuse of
    an already-revoked token — triggering it on a benign logout would self-DoS
    the user's other sessions. Unknown / already-revoked tokens are no-ops.
    """
    await session.execute(
        update(RefreshToken)
        .where(RefreshToken.token_hash == _hash(raw_token))
        .values(revoked=True)
    )
    await session.commit()
