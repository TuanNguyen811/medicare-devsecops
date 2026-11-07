from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings read from environment variables (no prefix)."""

    env: Literal["development", "test", "production"] = "development"
    database_url: str
    secret_key: SecretStr = Field(min_length=32)
    session_max_age: int = 28800
