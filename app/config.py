"""Application settings — the prod contract, loaded from env only.

Every field is required: a missing key raises at startup rather than falling back
to a hardcoded default that would silently run with wrong config (F12).
TEST_DATABASE_URL is intentionally absent — it is test infrastructure, read
directly by the test suite, never part of the app's prod contract.
"""
from functools import lru_cache
from typing import Annotated

from pydantic import field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


def _split_csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    DATABASE_URL: str
    # NoDecode: read the env value as a raw string so parse_csv handles the
    # comma-separated form instead of pydantic-settings expecting JSON.
    ALLOWED_REDIRECT_URIS: Annotated[list[str], NoDecode]
    CORS_ORIGINS: Annotated[list[str], NoDecode]

    @field_validator("ALLOWED_REDIRECT_URIS", "CORS_ORIGINS", mode="before")
    @classmethod
    def parse_csv(cls, value):
        if isinstance(value, str):
            return _split_csv(value)
        return value


@lru_cache
def get_settings() -> Settings:
    return Settings()
