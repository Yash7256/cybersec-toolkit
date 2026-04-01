from functools import lru_cache
from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class DatabaseSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="DATABASE_", env_file=".env", extra="ignore")

    url: str = Field(default="postgresql+asyncpg://postgres:postgres@localhost:5432/cybersec")
    pool_size: int = Field(default=5, validation_alias="DATABASE_POOL_SIZE")
    max_overflow: int = Field(default=10, validation_alias="DATABASE_MAX_OVERFLOW")


class APISettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="APP_", env_file=".env", extra="ignore")

    name: str = Field(default="cybersec", validation_alias="APP_NAME")
    host: str = Field(default="0.0.0.0", validation_alias="APP_HOST")
    port: int = Field(default=8000, validation_alias="APP_PORT")
    debug: bool = Field(default=False, validation_alias="APP_DEBUG")
    secret_key: str = Field(default="change-this-in-production", validation_alias="APP_SECRET_KEY")


class CorsSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    origins: str = Field(default="http://localhost:3000", validation_alias="CORS_ORIGINS")

    @property
    def origins_list(self) -> list[str]:
        return [origin.strip() for origin in self.origins.split(",") if origin.strip()]


class JWTSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="JWT_", env_file=".env", extra="ignore")

    algorithm: str = Field(default="HS256")
    expiration_minutes: int = Field(default=30)


class GroqSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="GROQ_", env_file=".env", extra="ignore")

    api_key: Optional[str] = Field(default=None)
    model: str = Field(default="llama-3.3-70b-versatile")


class EmailSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="EMAIL_", env_file=".env", extra="ignore")

    smtp_host: Optional[str] = Field(default=None)
    smtp_port: int = Field(default=587)
    from_address: Optional[str] = Field(default=None)
    password: Optional[str] = Field(default=None)


class SlackSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    webhook_url: Optional[str] = Field(default=None)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database: DatabaseSettings = Field(default_factory=DatabaseSettings)
    api: APISettings = Field(default_factory=APISettings)
    cors: CorsSettings = Field(default_factory=CorsSettings)
    jwt: JWTSettings = Field(default_factory=JWTSettings)
    groq: GroqSettings = Field(default_factory=GroqSettings)
    email: EmailSettings = Field(default_factory=EmailSettings)
    slack: SlackSettings = Field(default_factory=SlackSettings)


@lru_cache
def get_settings() -> Settings:
    return Settings()
