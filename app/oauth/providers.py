"""OAuth provider registry + the HTTP boundary to each provider (F8).

The registry holds the per-provider OAuth endpoints; client_id / client_secret
are read from env (never hardcoded). exchange_code() and fetch_userinfo() are the
ONLY functions that talk to the real provider over HTTP — tests monkeypatch them
(no real credentials in this build), while all the surrounding logic (state, PKCE,
provisioning, one-time code) is exercised for real.
"""
import os
from dataclasses import dataclass

import httpx

SUPPORTED = ("naver", "kakao", "google")


class ProviderError(Exception):
    """Provider returned an error / malformed payload (incl. error-in-HTTP-200).

    Callback maps this to a clean 4xx — never let it surface as a 500.
    """


@dataclass(frozen=True)
class Provider:
    name: str
    authorize_url: str
    token_url: str
    userinfo_url: str
    default_scope: str  # built-in scope; overridable per-deployment via {NAME}_SCOPE env

    @property
    def client_id(self) -> str:
        return os.environ.get(f"{self.name.upper()}_CLIENT_ID", "")

    @property
    def client_secret(self) -> str:
        return os.environ.get(f"{self.name.upper()}_CLIENT_SECRET", "")

    @property
    def scope(self) -> str:
        # {NAME}_SCOPE overrides the default (set "" to omit scope — e.g. Kakao
        # pre-review can't request account_email, so default scope is empty and the
        # authorize URL omits the param → app's default consent → user id, no email).
        return os.environ.get(f"{self.name.upper()}_SCOPE", self.default_scope)


_REGISTRY = {
    "naver": Provider(
        "naver",
        "https://nid.naver.com/oauth2.0/authorize",
        "https://nid.naver.com/oauth2.0/token",
        "https://openapi.naver.com/v1/nid/me",
        default_scope="name email",
    ),
    "kakao": Provider(
        "kakao",
        "https://kauth.kakao.com/oauth/authorize",
        "https://kauth.kakao.com/oauth/token",
        "https://kapi.kakao.com/v2/user/me",
        # Empty by default: pre-review apps can't request account_email (→ invalid_scope
        # at authorize). Set KAKAO_SCOPE=account_email after Kakao business-app review.
        default_scope="",
    ),
    "google": Provider(
        "google",
        "https://accounts.google.com/o/oauth2/v2/auth",
        "https://oauth2.googleapis.com/token",
        "https://openidconnect.googleapis.com/v1/userinfo",
        default_scope="openid email profile",
    ),
}


def get_provider(name: str) -> Provider | None:
    return _REGISTRY.get(name)


async def exchange_code(provider: Provider, code: str, code_verifier: str, redirect_uri: str) -> dict:
    """Exchange an authorization code (+ PKCE verifier) for the provider token set.

    Real HTTP — mocked in tests. Returns the provider's raw token JSON.
    """
    async with httpx.AsyncClient(timeout=10) as client:
        try:
            resp = await client.post(
                provider.token_url,
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "code_verifier": code_verifier,
                    "client_id": provider.client_id,
                    "client_secret": provider.client_secret,
                    "redirect_uri": redirect_uri,
                },
            )
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPError as exc:
            raise ProviderError(f"token exchange failed: {exc}") from exc
        except ValueError as exc:
            raise ProviderError(f"token response not JSON: {exc}") from exc


async def fetch_userinfo(provider: Provider, access_token: str) -> dict:
    """Fetch + NORMALIZE the provider profile to {provider_uid, email, email_verified}.

    Each provider returns a different shape; the callback only ever sees the
    normalized form. Real HTTP — tests mock only the transport and feed REAL
    provider-shaped payloads so this normalization actually runs.
    """
    async with httpx.AsyncClient(timeout=10) as client:
        try:
            resp = await client.get(
                provider.userinfo_url,
                headers={"Authorization": f"Bearer {access_token}"},
            )
            resp.raise_for_status()
            data = resp.json()
        except httpx.HTTPError as exc:
            raise ProviderError(f"userinfo fetch failed: {exc}") from exc
        except ValueError as exc:
            raise ProviderError(f"userinfo not JSON: {exc}") from exc
    return _normalize_userinfo(provider.name, data)


# Truthy values a provider may send for "email verified". Explicit set, NOT bool():
# bool("false") == True would let a string "false" pass the verified-email trust gate.
_VERIFIED_TRUE = {True, "true", "True", "TRUE", 1, "1"}


def _is_verified(value) -> bool:
    return value in _VERIFIED_TRUE


def _normalize_userinfo(provider_name: str, data: dict) -> dict:
    """Map each provider's raw userinfo shape → {provider_uid, email, email_verified}.

    Providers can return an error/empty payload with HTTP 200 (notably Naver:
    {resultcode!="00", no response}). A missing provider uid raises ProviderError
    so the callback maps it to a clean 4xx — never an unguarded subscript KeyError
    (→500). email_verified uses explicit truthiness (a security gate, see _is_verified).
    """
    if provider_name == "google":
        # Google OIDC userinfo: {sub, email, email_verified, ...}
        uid = data.get("sub")
        if not uid:
            raise ProviderError("google userinfo missing sub")
        return {
            "provider_uid": str(uid),
            "email": data.get("email"),
            "email_verified": _is_verified(data.get("email_verified")),
        }
    if provider_name == "kakao":
        # Kakao: {id, kakao_account: {email, is_email_verified, ...}}
        uid = data.get("id")
        if not uid:
            raise ProviderError("kakao userinfo missing id")
        account = data.get("kakao_account") or {}
        return {
            "provider_uid": str(uid),
            "email": account.get("email"),
            "email_verified": _is_verified(account.get("is_email_verified")),
        }
    if provider_name == "naver":
        # Naver wraps the profile in {response:{id,email,...}} on success, but auth
        # fail/cancel returns HTTP 200 + {resultcode!="00", message, NO response}.
        if data.get("resultcode") not in (None, "00"):
            raise ProviderError(f"naver auth failed: {data.get('message') or data.get('resultcode')}")
        response = data.get("response") or {}
        uid = response.get("id")
        if not uid:
            raise ProviderError("naver userinfo missing response.id")
        email = response.get("email")
        # Naver has no explicit verified flag → a present (account-verified) email
        # is treated as verified (assumption: Naver only returns the verified email).
        return {
            "provider_uid": str(uid),
            "email": email,
            "email_verified": bool(email),
        }
    raise ValueError(f"unknown provider for userinfo normalization: {provider_name}")
