"""
Configuration for CyberSec.
"""
import logging
from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    DATABASE_URL: str = "postgresql+asyncpg://postgres:postgres@localhost:5432/cybersec"
    DATABASE_SYNC_URL: str = ""  # psycopg2 URL used only by Alembic migrations
    DATABASE_POOL_SIZE: int = 5
    DATABASE_MAX_OVERFLOW: int = 10
    APP_NAME: str = "cybersec"
    APP_HOST: str = "0.0.0.0"
    APP_PORT: int = 8000
    APP_DEBUG: bool = False
    WORKERS: int = 1
    CORS_ORIGINS: str = "http://localhost:3000,http://localhost:8080"

    # Clerk Auth
    CLERK_PUBLISHABLE_KEY: str = ""
    CLERK_SECRET_KEY: str = ""
    CLERK_JWKS_URL: str = ""
    CLERK_ISSUER: str = ""
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
    SSL_AUDIT_TIMEOUT_SECONDS: int = 20

    # GeoIP provider configuration
    GEOIP_PROVIDER: str = "ipwhois"
    GEOIP_TIMEOUT: float = 5.0
    GEOIP_CACHE_TTL_SECONDS: int = 3600
    GEOIP_CACHE_MAX_ENTRIES: int = 10000
    GEOIP_CACHE_SWEEP_INTERVAL_SECONDS: int = 300
    GEOIP_ALLOW_PRIVATE_TARGETS: bool = False
    GEOIP_MAX_CONCURRENT_LOOKUPS: int = 5
    GEOIP_RATE_LIMIT_PER_MINUTE: int = 55

    # WHOIS configuration
    WHOIS_CACHE_TTL_SECONDS: int = 3600
    WHOIS_TIMEOUT: float = 8.0
    RDAP_BOOTSTRAP_URL: str = "https://rdap.org"
    RDAP_FALLBACK_URLS: str = "https://rdap.iana.org"
    RDAP_MAX_RETRIES: int = 2
    RDAP_RETRY_DELAY_SECONDS: float = 0.5
    WHOIS_PRIVACY_PATTERNS: str = "privacy,redacted,whoisguard,domains by proxy,contact privacy,data protected,private registration,withheld"
    WHOIS_SUSPICIOUS_STATUS_TOKENS: str = "hold,pendingdelete,redemptionperiod,serverdeleteprohibited,clienthold"
    WHOIS_COMMON_TLDS: str = "com,org,net,edu,gov,io,co,in,uk,de,fr,au,ca,us,info,biz,dev,app,ai,me,xyz"

    # Threat intelligence configuration
    ABUSEIPDB_API_KEY: str = ""
    THREAT_INTEL_MAX_AGE_DAYS: int = 90

    # Port scan safety limits
    MAX_PORT_RANGE_SIZE: int = 5000    # max end_port - start_port inclusive
    MAX_PORTS_LIST_SIZE: int = 1000    # max entries in the explicit ports list
    ALLOW_PRIVATE_TARGET_SCANS: bool = False  # bypass private-IP block for auth'd callers

    # Port screenshot capture (requires `playwright install chromium` after pip install)
    ENABLE_PORT_SCREENSHOTS: bool = True

    # Web app scanner limits
    WEBAPP_SCAN_MAX_DURATION_SECONDS: int = 300   # 5-minute wall-clock budget per scan
    WEBAPP_SCAN_STATE_TTL_SECONDS: int = 3600     # evict in-memory scan state after 1 hour

    # Caching TTLs for expensive per-scan operations
    THREAT_INTEL_CACHE_TTL_SECONDS: int = 3600   # 1 hour
    AI_RECOMMENDATIONS_CACHE_TTL_SECONDS: int = 86400  # 24 hours
    OS_FINGERPRINT_CACHE_TTL_SECONDS: int = 1800  # 30 minutes
    PING_HISTORY_TTL_SECONDS: int = 3600  # 1 hour
    TRACEROUTE_TIMEOUT_SECONDS: int = 60  # max wall-clock budget for the traceroute subprocess
    HOP_INFO_CACHE_TTL_SECONDS: int = 86400  # 24 hours — router hostnames are stable

    @property
    def clerk_configured(self) -> bool:
        """Return True if both Clerk JWKS URL and issuer are configured."""
        return bool(self.CLERK_JWKS_URL and self.CLERK_ISSUER)

    @property
    def whois_privacy_patterns_list(self) -> list[str]:
        return [p.strip().lower() for p in self.WHOIS_PRIVACY_PATTERNS.split(",") if p.strip()]

    @property
    def whois_suspicious_status_tokens_list(self) -> list[str]:
        return [t.strip().lower() for t in self.WHOIS_SUSPICIOUS_STATUS_TOKENS.split(",") if t.strip()]

    @property
    def whois_common_tlds_set(self) -> set[str]:
        return {t.strip().lower() for t in self.WHOIS_COMMON_TLDS.split(",") if t.strip()}

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

# Warn at startup if Clerk is not configured — authenticated requests will return 503
if not settings.clerk_configured:
    logger.warning(
        "CLERK_JWKS_URL and/or CLERK_ISSUER are not set. "
        "All authenticated requests will be rejected with HTTP 503 "
        "until these values are provided in the environment."
    )

# TODO: implement additional config logic if needed
