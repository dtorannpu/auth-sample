from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    authorization_url: str = Field(default="", min_length=1)
    token_url: str = Field(default="", min_length=1)
    jwks_url: str = Field(default="", min_length=1)
    issuer: str = Field(default="", min_length=1)
    audience: list[str] = Field(default_factory=list, min_length=1)

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")


def get_settings() -> Settings:
    """設定を取得する"""
    return Settings()
