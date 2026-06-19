"""phase3.ckpt2 #20 — JWT access tokens, RS256, adversarial (F4, audit #3).

issue_access(user) → RS256 JWT signed with the env private key, TTL clamped at
<=900s. verify_access(token) → claims, or raises on tamper / expiry / wrong key.
Keys are loaded from env paths, never hardcoded.
"""
import time

import jwt
import pytest

from app.tokens import issue_access, verify_access, TokenError


class _User:
    def __init__(self, id=1, email="a@b.com"):
        self.id = id
        self.email = email


def test_access_is_rs256_and_carries_subject():
    token = issue_access(_User(id=7))
    header = jwt.get_unverified_header(token)
    assert header["alg"] == "RS256"
    claims = verify_access(token)
    assert str(claims["sub"]) == "7"


def test_access_ttl_clamped_at_900(monkeypatch):
    # Even with a larger env TTL, exp-iat must never exceed 900 (audit #3).
    monkeypatch.setenv("ACCESS_TTL", "100000")
    token = issue_access(_User())
    claims = verify_access(token)
    assert claims["exp"] - claims["iat"] <= 900


def test_access_ttl_uses_env_when_below_cap(monkeypatch):
    monkeypatch.setenv("ACCESS_TTL", "300")
    token = issue_access(_User())
    claims = verify_access(token)
    assert claims["exp"] - claims["iat"] == 300


def test_access_verify_rejects_tampered_token():
    token = issue_access(_User())
    # Flip the last char of the payload/signature region.
    tampered = token[:-3] + ("aaa" if token[-3:] != "aaa" else "bbb")
    with pytest.raises(TokenError):
        verify_access(tampered)


def test_access_verify_rejects_expired_token(monkeypatch):
    monkeypatch.setenv("ACCESS_TTL", "1")
    token = issue_access(_User())
    time.sleep(2)
    with pytest.raises(TokenError):
        verify_access(token)


def test_access_verify_rejects_token_signed_with_wrong_key():
    # A token signed by an unrelated RSA key must not verify against our public key.
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization

    pk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = pk.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    forged = jwt.encode({"sub": "1"}, pem, algorithm="RS256")
    with pytest.raises(TokenError):
        verify_access(forged)
