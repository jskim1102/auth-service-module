"""phase3.ckpt1 #18 — the four SQLAlchemy models and their constraints (F1).

users/auth_identities/refresh_tokens/password_resets. SNS-only users keep
username + password_hash NULL (zero-friction). refresh_tokens carries chain_id
(CTO-approved option A) so reuse-detection can revoke a whole rotation family.
"""
from app.db import Base
from app.models import AuthIdentity, PasswordReset, RefreshToken, User


def _col(model, name):
    return model.__table__.columns[name]


def test_all_four_tables_registered():
    tables = set(Base.metadata.tables)
    assert {"users", "auth_identities", "refresh_tokens", "password_resets"} <= tables


def test_user_nullability_and_unique():
    # SNS-only / id-only provisioning: username, password_hash, AND email are all
    # nullable (#26 — Kakao pre-email-review / Apple Hide-My-Email have no email).
    assert _col(User, "username").nullable is True
    assert _col(User, "password_hash").nullable is True
    assert _col(User, "email").nullable is True
    assert _col(User, "email").unique is True  # UNIQUE kept (Postgres allows many NULLs)
    assert _col(User, "username").unique is True


def test_auth_identity_composite_unique():
    uniques = [
        tuple(c.name for c in con.columns)
        for con in AuthIdentity.__table__.constraints
        if con.__class__.__name__ == "UniqueConstraint"
    ]
    assert ("provider", "provider_uid") in uniques


def test_auth_identity_user_fk():
    fks = {fk.column.table.name for fk in _col(AuthIdentity, "user_id").foreign_keys}
    assert "users" in fks


def test_refresh_token_has_chain_id_and_hash_fields():
    # chain_id (option A) links a rotation family for reuse-detection.
    cols = RefreshToken.__table__.columns
    assert "chain_id" in cols
    assert "token_hash" in cols
    assert "expires_at" in cols
    assert _col(RefreshToken, "revoked").nullable is False
    fks = {fk.column.table.name for fk in _col(RefreshToken, "user_id").foreign_keys}
    assert "users" in fks


def test_password_reset_fields():
    cols = PasswordReset.__table__.columns
    assert {"token_hash", "user_id", "expires_at", "used"} <= set(cols.keys())
    fks = {fk.column.table.name for fk in _col(PasswordReset, "user_id").foreign_keys}
    assert "users" in fks
