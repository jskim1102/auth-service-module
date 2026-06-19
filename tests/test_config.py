"""phase3.ckpt0 #16 — Settings loads the prod contract from env, no fallback (F12)."""
import pytest
from pydantic import ValidationError

from app.config import Settings

# A complete, valid env for the prod contract. Lists are comma-separated in env.
VALID_ENV = {
    "DATABASE_URL": "postgresql+asyncpg://postgres:postgres@postgres:5432/auth",
    "ALLOWED_REDIRECT_URIS": "http://localhost:5176/auth/callback,https://app.example.com/cb",
    "CORS_ORIGINS": "http://localhost:5176,https://app.example.com",
}


def _build():
    # _env_file=None isolates the test from the real .env so we assert the pure
    # env-var contract (the no-fallback behavior, not what .env happens to hold).
    return Settings(_env_file=None)


def test_loads_all_three_keys_from_env(monkeypatch):
    for k, v in VALID_ENV.items():
        monkeypatch.setenv(k, v)
    s = _build()
    assert s.DATABASE_URL == VALID_ENV["DATABASE_URL"]


def test_lists_parse_to_multiple_entries(monkeypatch):
    for k, v in VALID_ENV.items():
        monkeypatch.setenv(k, v)
    s = _build()
    assert s.ALLOWED_REDIRECT_URIS == [
        "http://localhost:5176/auth/callback",
        "https://app.example.com/cb",
    ]
    assert s.CORS_ORIGINS == ["http://localhost:5176", "https://app.example.com"]


@pytest.mark.parametrize("missing", list(VALID_ENV.keys()))
def test_missing_key_raises_no_fallback(monkeypatch, missing):
    """Any missing key must raise — no hardcoded default keeps the app running (F12)."""
    for k, v in VALID_ENV.items():
        monkeypatch.setenv(k, v)
    monkeypatch.delenv(missing, raising=False)
    with pytest.raises(ValidationError):
        _build()


def test_test_database_url_is_not_part_of_settings(monkeypatch):
    """TEST_DATABASE_URL is test-only infra, never in the app's prod Settings contract."""
    for k, v in VALID_ENV.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setenv("TEST_DATABASE_URL", "postgresql+asyncpg://postgres:postgres@localhost:5435/auth")
    s = _build()
    assert not hasattr(s, "TEST_DATABASE_URL")
