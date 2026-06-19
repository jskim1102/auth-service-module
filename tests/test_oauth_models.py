"""phase6 ← F8 — oauth_states + oauth_codes models (A안, additive).

OAuth needs two server-side single-use, time-limited, hashed stores:
  - oauth_states: CSRF state + PKCE code_verifier between authorize and callback.
  - oauth_codes:   the short-lived one-time code between callback and exchange.
Both follow the password_resets/refresh_tokens pattern (hash + expires_at + used)
so they can be consumed atomically (UPDATE ... WHERE used=false RETURNING).
"""
from app.db import Base
from app.models import OAuthCode, OAuthState


def _col(model, name):
    return model.__table__.columns[name]


def test_oauth_tables_registered():
    tables = set(Base.metadata.tables)
    assert {"oauth_states", "oauth_codes"} <= tables


def test_oauth_state_fields():
    cols = OAuthState.__table__.columns
    assert {"state_hash", "code_verifier", "provider", "expires_at", "used"} <= set(cols.keys())
    assert _col(OAuthState, "state_hash").unique is True
    assert _col(OAuthState, "used").nullable is False


def test_oauth_code_fields_and_user_fk():
    cols = OAuthCode.__table__.columns
    assert {"code_hash", "user_id", "expires_at", "used"} <= set(cols.keys())
    assert _col(OAuthCode, "code_hash").unique is True
    assert _col(OAuthCode, "used").nullable is False
    fks = {fk.column.table.name for fk in _col(OAuthCode, "user_id").foreign_keys}
    assert "users" in fks
