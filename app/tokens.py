"""JWT access tokens — RS256, short-lived (F4, audit #3).

Keys are loaded from the env-configured PEM paths (never hardcoded). The access
TTL is clamped at MAX_ACCESS_TTL so a misconfigured ACCESS_TTL cannot mint a
long-lived bearer token.
"""
import base64
import hashlib
import json
import os
import time
from functools import lru_cache

import jwt
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from jwt.algorithms import RSAAlgorithm

ALGORITHM = "RS256"
MAX_ACCESS_TTL = 900  # seconds — hard cap regardless of env (audit #3).


class TokenError(Exception):
    """Raised when a token fails verification (tamper, expiry, wrong key)."""


@lru_cache
def _private_key() -> str:
    with open(os.environ["JWT_PRIVATE_KEY_PATH"], "r") as f:
        return f.read()


@lru_cache
def _public_key() -> str:
    with open(os.environ["JWT_PUBLIC_KEY_PATH"], "r") as f:
        return f.read()


def _access_ttl() -> int:
    return min(int(os.environ.get("ACCESS_TTL", MAX_ACCESS_TTL)), MAX_ACCESS_TTL)


@lru_cache
def public_jwk() -> dict:
    """The RS256 PUBLIC key as a JWK (kty/n/e + kid). No private components.

    Single source of truth for both the token header `kid` and the JWKS endpoint,
    so the two always match (host can select the right key by kid).
    """
    pubkey = load_pem_public_key(_public_key().encode())
    jwk = json.loads(RSAAlgorithm.to_jwk(pubkey))  # public-only: kty, n, e
    # RFC 7638 thumbprint over the canonical {e,kty,n} → deterministic kid.
    canonical = json.dumps(
        {"e": jwk["e"], "kty": jwk["kty"], "n": jwk["n"]},
        separators=(",", ":"),
        sort_keys=True,
    )
    kid = base64.urlsafe_b64encode(hashlib.sha256(canonical.encode()).digest()).decode().rstrip("=")
    return {"kty": jwk["kty"], "n": jwk["n"], "e": jwk["e"], "use": "sig", "alg": ALGORITHM, "kid": kid}


def _kid() -> str:
    return public_jwk()["kid"]


def issue_access(user) -> str:
    now = int(time.time())
    claims = {
        "sub": str(user.id),
        "email": getattr(user, "email", None),
        "iat": now,
        "exp": now + _access_ttl(),
    }
    # Stamp the kid so a host (via JWKS) can pick the matching key (note1).
    return jwt.encode(claims, _private_key(), algorithm=ALGORITHM, headers={"kid": _kid()})


def verify_access(token: str) -> dict:
    try:
        return jwt.decode(token, _public_key(), algorithms=[ALGORITHM])
    except jwt.PyJWTError as exc:
        raise TokenError(str(exc)) from exc
