from typing import Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings read from environment variables (no prefix)."""

    # hide_input_in_errors: a rejected secret must never appear in ValidationError text.
    model_config = SettingsConfigDict(hide_input_in_errors=True)

    env: Literal["development", "test", "production"] = "development"
    database_url: str
    secret_key: SecretStr = Field(min_length=32)
    session_max_age: int = Field(default=28800, ge=300, le=86400)

    @field_validator("secret_key")
    @classmethod
    def _reject_placeholder_secret(cls, value: SecretStr) -> SecretStr:
        if "change-me" in value.get_secret_value().lower():
            raise ValueError("secret_key must not be a placeholder value")
        return value
