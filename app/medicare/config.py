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
    # Prometheus metrics on their own port; off unless set. Deployments that scrape the
    # app from another pod set METRICS_HOST to the pod address range they listen on.
    metrics_port: int | None = Field(default=None, ge=1, le=65535)
    metrics_host: str = "127.0.0.1"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    @field_validator("secret_key")
    @classmethod
    def _reject_placeholder_secret(cls, value: SecretStr) -> SecretStr:
        if "change-me" in value.get_secret_value().lower():
            raise ValueError("secret_key must not be a placeholder value")
        return value
