"""
Configuration for CyberSec.
"""
from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    DATABASE_URL: str = "postgresql+asyncpg://postgres:postgres@localhost:5432/cybersec"
    DATABASE_POOL_SIZE: int = 5
    DATABASE_MAX_OVERFLOW: int = 10
    APP_NAME: str = "cybersec"
    APP_HOST: str = "0.0.0.0"
    APP_PORT: int = 8000
    APP_DEBUG: bool = False
    APP_SECRET_KEY: str = "change-this-to-a-random-64-char-string-in-production"
    CORS_ORIGINS: str = "http://localhost:3000,http://localhost:8080"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRATION_MINUTES: int = 30
    REDIS_URL: str = "redis://localhost:6379/0"
    ENABLE_SERVICE_DETECTION: bool = True
    ENABLE_ATTACK_MAPPING: bool = True
    SERVICE_DETECTION_CONCURRENCY: int = 25
    
    # Groq API Keys (multiple for rotation)
    GROQ_API_KEY: str = ""
    GROQ_API_KEY_1: Optional[str] = None
    GROQ_API_KEY_2: Optional[str] = None
    GROQ_API_KEY_3: Optional[str] = None
    GROQ_API_KEY_4: Optional[str] = None
    GROQ_API_KEY_5: Optional[str] = None
    GROQ_MODEL: str = "llama-3.3-70b-versatile"
    
    # Google Gemini API
    GEMINI_API_KEY: str = ""
    GEMINI_MODEL: str = "gemini-2.0-flash"
    
    SLACK_WEBHOOK_URL: str = ""
    EMAIL_SMTP_HOST: str = ""
    
    # NVD API 2.0 Configuration
    NVD_API_KEY: Optional[str] = None    # read from env var NVD_API_KEY
    NVD_RATE_LIMIT: float = 6.0          # auto-adjusted to 0.6 if API key present
    NVD_CACHE_TTL_HOURS: int = 24
    NVD_MAX_RESULTS_PER_SERVICE: int = 10
    NVD_MIN_CVSS_SCORE: float = 5.0
    
    # Scanner timeout settings
    SCAN_TIMEOUT: float = 10.0
    OS_FINGERPRINT_TIMEOUT: float = 5.0
    SERVICE_DETECTION_TIMEOUT: float = 8.0

    @property
    def cors_origins_list(self) -> list[str]:
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",") if origin.strip()]
    
    def get_groq_keys(self) -> list[str]:
        keys = []
        for i in range(1, 6):
            key = getattr(self, f"GROQ_API_KEY_{i}", None)
            if key:
                keys.append(key)
        if self.GROQ_API_KEY and self.GROQ_API_KEY not in keys:
            keys.insert(0, self.GROQ_API_KEY)
        return keys
    
    def get_available_providers(self) -> list[dict]:
        providers = []
        if self.get_groq_keys():
            providers.append({"name": "groq", "priority": 1})
        if self.GEMINI_API_KEY:
            providers.append({"name": "gemini", "priority": 2})
        return providers


settings = Settings()

# TODO: implement additional config logic if needed
