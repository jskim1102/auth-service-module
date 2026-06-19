"""phase3.ckpt0 #17 — redirect whitelist (open-redirect defense, audit #2/#5).

is_allowed_redirect(url) returns True only for an EXACT match against
Settings.ALLOWED_REDIRECT_URIS. Every near-miss must return False — this is the
foundation phase6 OAuth callback relies on to reject attacker-controlled hosts.
"""
import pytest

from app.security.redirects import is_allowed_redirect

WHITELIST = "https://app.example.com/auth/callback,https://web.example.com/cb"


@pytest.fixture(autouse=True)
def _set_whitelist(monkeypatch):
    # Settings reads the list from env; set a known two-entry whitelist.
    monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://u:p@h:5432/d")
    monkeypatch.setenv("ALLOWED_REDIRECT_URIS", WHITELIST)
    monkeypatch.setenv("CORS_ORIGINS", "https://app.example.com")
    # get_settings is lru_cached — clear so each test sees fresh env.
    from app.config import get_settings
    get_settings.cache_clear()


def test_exact_whitelisted_urls_allowed():
    assert is_allowed_redirect("https://app.example.com/auth/callback") is True
    assert is_allowed_redirect("https://web.example.com/cb") is True


@pytest.mark.parametrize(
    "url",
    [
        "https://app.example.com",                              # missing path
        "https://app.example.com/auth/callback/extra",          # extra path segment
        "https://app.example.com/auth/callback?next=evil",      # trailing query junk
        "https://app.example.com/auth/callback#frag",           # trailing fragment
        "https://app.example.com.evil.com/auth/callback",       # suffix host trick
        "https://evil.com/auth/callback",                       # different host
        "https://evilapp.example.com/auth/callback",            # prefix host trick
        "http://app.example.com/auth/callback",                 # scheme swap http
        "https://app.example.com:443/auth/callback",            # explicit port mismatch
        "https://app.example.com/auth/callback ",               # trailing whitespace
        "//app.example.com/auth/callback",                      # scheme-relative
        "",                                                     # empty
        "https://web.example.com/cb/",                          # trailing slash
    ],
)
def test_near_miss_urls_rejected(url):
    assert is_allowed_redirect(url) is False
