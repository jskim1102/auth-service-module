"""Redirect URL whitelist — open-redirect defense (audit #2/#5).

phase6 OAuth callback redirects the browser to a host-supplied URL. Only an
EXACT match against Settings.ALLOWED_REDIRECT_URIS is permitted; any near-miss
(suffix/prefix host trick, scheme swap, extra path, trailing query/fragment) is
rejected so an attacker cannot smuggle tokens to a controlled host.
"""
from app.config import get_settings


def is_allowed_redirect(url: str) -> bool:
    """True only when url exactly equals a whitelisted redirect URI."""
    return url in get_settings().ALLOWED_REDIRECT_URIS
