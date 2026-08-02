"""Outbound email — password-reset delivery via SMTP (F7).

Sends through the env-configured SMTP server (SMTP_HOST/SMTP_PORT/SMTP_FROM).
Optional SMTP_USER/SMTP_PASSWORD (auth) and SMTP_STARTTLS (bool) support real
providers like Gmail. Defaults (no user/pass, STARTTLS off) = MailHog (no auth,
plaintext), so the demo stack is unchanged. The reset email carries the raw
token; only its hash is stored (see auth_reset). Tests mock the send.
"""
import os
from email.message import EmailMessage

import aiosmtplib


def _truthy(value: str | None) -> bool:
    return (value or "").lower() in ("1", "true", "yes", "on")


async def send_reset_email(to_email: str, token: str) -> None:
    message = EmailMessage()
    message["From"] = os.environ["SMTP_FROM"]
    message["To"] = to_email
    message["Subject"] = "Password reset"
    # Clickable link → the SPA /reset page prefills the token from ?token= (#32).
    # APP_BASE_URL is the public base the user reaches the app at. The raw token is
    # kept too as a fallback for manual entry.
    reset_url = f"{os.environ['APP_BASE_URL'].rstrip('/')}/reset?token={token}"
    message.set_content(
        "A password reset was requested for your account.\n\n"
        f"Reset your password: {reset_url}\n\n"
        f"(Or enter this token manually: {token})\n\n"
        "If you did not request this, you can ignore this email."
    )
    await _deliver(message)


async def _deliver(message: EmailMessage) -> None:
    """Send via the env-configured SMTP. Optional auth + STARTTLS (real SMTP);
    empty user/pass + STARTTLS off = MailHog (the demo default)."""
    kwargs = {
        "hostname": os.environ["SMTP_HOST"],
        "port": int(os.environ["SMTP_PORT"]),
        "start_tls": _truthy(os.environ.get("SMTP_STARTTLS")),
    }
    user = os.environ.get("SMTP_USER")
    password = os.environ.get("SMTP_PASSWORD")
    if user:
        kwargs["username"] = user
        kwargs["password"] = password
    await aiosmtplib.send(message, **kwargs)


async def send_username_email(to_email: str, username: str) -> None:
    """Email a user their username for account recovery (아이디 찾기). No link/token —
    a username isn't secret to its owner, and delivery to the registered email IS the
    ownership check (same trust model as the reset email). Tests mock the send."""
    message = EmailMessage()
    message["From"] = os.environ["SMTP_FROM"]
    message["To"] = to_email
    message["Subject"] = "Your username"
    message.set_content(
        "You requested to recover the username for your account.\n\n"
        f"Your username is: {username}\n\n"
        "Sign in with this username (or your email) and your password.\n"
        "If you did not request this, you can ignore this email."
    )
    await _deliver(message)
