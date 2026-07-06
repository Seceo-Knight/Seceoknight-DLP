"""
Configuration Management
Centralized configuration using Pydantic Settings
"""

import json
from typing import List, Optional
from pydantic import Field, field_validator, PostgresDsn, MongoDsn, RedisDsn
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables
    """

    # Application Info
    PROJECT_NAME: str = "SeceoKnight DLP"
    PROJECT_DESCRIPTION: str = "Enterprise Data Loss Prevention Platform"
    VERSION: str = "2.0.0"
    ENVIRONMENT: str = Field(default="development")
    DEBUG: bool = Field(default=False)

    # Server Configuration
    HOST: str = Field(default="0.0.0.0")
    PORT: int = Field(default=55000)
    WORKERS: int = Field(default=4)
    API_V1_PREFIX: str = "/api/v1"

    # Security
    SECRET_KEY: str = Field(...)
    # Separate key for Fernet encryption (OAuth tokens). Falls back to SECRET_KEY if not set.
    ENCRYPTION_KEY: str = Field(default="")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 1  # 24 hours — enterprise security policy
    PASSWORD_MIN_LENGTH: int = 7

    # SSO — shared secret for verifying exchange tokens from the SIEM.
    # If empty/unset, the /auth/sso/exchange endpoint returns 503 (SSO disabled).
    # This is NOT the same as SECRET_KEY. The SIEM signs its exchange token
    # with DLP_SSO_SECRET; the DLP verifies it with DLP_SSO_SECRET then issues
    # its own tokens signed with SECRET_KEY.
    DLP_SSO_SECRET: str = Field(default="")

    # CORS
    # NOTE: Pydantic Settings parses list fields from env as JSON only. To support both:
    # - JSON list strings (recommended) AND
    # - comma-separated strings
    # we allow either str or List[str] as input and normalize via validators below.
    CORS_ORIGINS: List[str] | str = Field(
        default=["*"]
    )
    ALLOWED_HOSTS: List[str] | str = Field(default=["*"])

    # PostgreSQL Configuration
    POSTGRES_HOST: str = Field(default="localhost")
    POSTGRES_PORT: int = Field(default=5432)
    POSTGRES_USER: str = Field(default="dlp_user")
    POSTGRES_PASSWORD: str = Field(...)
    POSTGRES_DB: str = Field(default="seceoknight_dlp")
    POSTGRES_POOL_SIZE: int = Field(default=20)
    POSTGRES_MAX_OVERFLOW: int = Field(default=10)

    @property
    def DATABASE_URL(self) -> str:
        """Construct PostgreSQL connection URL"""
        return str(PostgresDsn.build(
            scheme="postgresql+asyncpg",
            username=self.POSTGRES_USER,
            password=self.POSTGRES_PASSWORD,
            host=self.POSTGRES_HOST,
            port=self.POSTGRES_PORT,
            path=self.POSTGRES_DB,
        ))

    # MongoDB Configuration
    MONGODB_HOST: str = Field(default="localhost")
    MONGODB_PORT: int = Field(default=27017)
    MONGODB_USER: str = Field(default="dlp_user")
    MONGODB_PASSWORD: str = Field(...)
    MONGODB_DB: str = Field(default="seceoknight_dlp")
    MONGODB_MAX_POOL_SIZE: int = Field(default=100)

    @property
    def MONGODB_URL(self) -> str:
        """Construct MongoDB connection URL"""
        return str(MongoDsn.build(
            scheme="mongodb",
            username=self.MONGODB_USER,
            password=self.MONGODB_PASSWORD,
            host=self.MONGODB_HOST,
            port=self.MONGODB_PORT,
            path=self.MONGODB_DB,
            query="authSource=admin",
        ))

    # Redis Configuration
    REDIS_HOST: str = Field(default="localhost")
    REDIS_PORT: int = Field(default=6379)
    REDIS_PASSWORD: Optional[str] = Field(default=None)
    REDIS_DB: int = Field(default=0)
    REDIS_POOL_SIZE: int = Field(default=10)

    @property
    def REDIS_URL(self) -> str:
        """Construct Redis connection URL"""
        return str(RedisDsn.build(
            scheme="redis",
            password=self.REDIS_PASSWORD,
            host=self.REDIS_HOST,
            port=self.REDIS_PORT,
            path=str(self.REDIS_DB),
        ))

    # OpenSearch Configuration
    OPENSEARCH_HOST: str = Field(default="localhost")
    OPENSEARCH_PORT: int = Field(default=9200)
    OPENSEARCH_USER: str = Field(default="admin")
    OPENSEARCH_PASSWORD: str = Field(...)
    OPENSEARCH_USE_SSL: bool = Field(default=True)
    OPENSEARCH_VERIFY_CERTS: bool = Field(default=False)
    OPENSEARCH_INDEX_PREFIX: str = Field(default="seceoknight")
    OPENSEARCH_RETENTION_DAYS: int = Field(default=90)

    # Event Retention Configuration
    EVENT_RETENTION_DAYS: int = Field(default=180)

    # Rate Limiting
    RATE_LIMIT_ENABLED: bool = Field(default=True)
    RATE_LIMIT_REQUESTS: int = Field(default=100)
    RATE_LIMIT_WINDOW: int = Field(default=60)

    # Timezone — controls display/API timestamps. Storage is always UTC.
    # Examples: "Asia/Kolkata", "US/Eastern", "Europe/London", "UTC"
    APP_TIMEZONE: str = Field(default="UTC")

    # Logging
    LOG_LEVEL: str = Field(default="INFO")
    LOG_FORMAT: str = Field(default="json")
    LOG_FILE: Optional[str] = Field(default=None)

    # Email Configuration (for alerts and scheduled reports)
    SMTP_HOST: str = Field(default="smtp.gmail.com")
    SMTP_PORT: int = Field(default=587)
    SMTP_TLS: bool = Field(default=True)
    SMTP_USER: Optional[str] = Field(default=None)
    SMTP_PASSWORD: Optional[str] = Field(default=None)
    SMTP_FROM: str = Field(default="noreply@seceoknight.com")
    SMTP_FROM_EMAIL: str = Field(default="noreply@seceoknight.com")
    SMTP_FROM_NAME: str = Field(default="SeceoKnight DLP")
    # Alert email recipients — comma-separated list loaded from env var ALERT_EMAIL_RECIPIENTS
    # e.g.  ALERT_EMAIL_RECIPIENTS=admin@company.com,security@company.com
    ALERT_EMAIL_RECIPIENTS: List[str] = Field(default_factory=list)
    # Minimum severity that triggers an automatic email: critical | high | medium | low
    ALERT_EMAIL_MIN_SEVERITY: str = Field(default="high")

    # Reports Storage
    REPORTS_DIR: str = Field(default="/app/reports")

    # Wazuh Integration
    WAZUH_HOST: str = Field(default="localhost")
    WAZUH_PORT: int = Field(default=1514)
    WAZUH_PROTOCOL: str = Field(default="udp")
    WAZUH_API_URL: Optional[str] = Field(default=None)
    WAZUH_API_USER: Optional[str] = Field(default=None)
    WAZUH_API_PASSWORD: Optional[str] = Field(default=None)

    # ML Configuration
    ML_MODEL_PATH: str = Field(default="./ml/models")
    ML_INFERENCE_BATCH_SIZE: int = Field(default=32)
    ML_CONFIDENCE_THRESHOLD: float = Field(default=0.75)

    # DLP Configuration
    DLP_MAX_FILE_SIZE_MB: int = Field(default=100)
    DLP_SCAN_TIMEOUT_SECONDS: int = Field(default=30)
    DLP_QUARANTINE_PATH: str = Field(default="./quarantine")

    # Classification Thresholds
    CLASSIFICATION_HIGH_RISK_THRESHOLD: float = Field(default=0.85)
    CLASSIFICATION_MEDIUM_RISK_THRESHOLD: float = Field(default=0.60)

    # Monitoring & Metrics
    METRICS_ENABLED: bool = Field(default=True)
    HEALTH_CHECK_INTERVAL: int = Field(default=30)

    # Feature Flags
    FEATURE_ML_CLASSIFICATION: bool = Field(default=True)
    FEATURE_REAL_TIME_BLOCKING: bool = Field(default=True)
    FEATURE_CLOUD_CONNECTORS: bool = Field(default=True)

    # Google Drive OAuth
    GOOGLE_CLIENT_ID: Optional[str] = Field(default=None)
    GOOGLE_CLIENT_SECRET: Optional[str] = Field(default=None)
    GOOGLE_REDIRECT_URI: Optional[str] = Field(default=None)
    GOOGLE_OAUTH_CREDENTIALS_PATH: Optional[str] = Field(default="credentials.json")

    # OneDrive OAuth
    ONEDRIVE_CLIENT_ID: Optional[str] = Field(default=None)
    ONEDRIVE_CLIENT_SECRET: Optional[str] = Field(default=None)
    ONEDRIVE_REDIRECT_URI: Optional[str] = Field(default=None)
    ONEDRIVE_TENANT_ID: Optional[str] = Field(default="consumers")  # "consumers" for personal accounts, "common" for both, or tenant ID for org accounts

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def parse_cors_origins(cls, v):
        """
        Parse CORS origins from env.

        Supports:
        - JSON list string: ["http://localhost:3000","http://192.168.1.63:3000"]
        - Comma-separated:  http://localhost:3000,http://192.168.1.63:3000
        """
        if v is None or (isinstance(v, str) and not v.strip()):
            # Explicit empty env should fall back to the Field default.
            default = cls.model_fields["CORS_ORIGINS"].default
            return list(default) if isinstance(default, list) else default
        return cls._parse_list_env(v, field_name="CORS_ORIGINS")

    @field_validator("ALLOWED_HOSTS", mode="before")
    @classmethod
    def parse_allowed_hosts(cls, v):
        """
        Parse allowed hosts from env.

        Supports:
        - JSON list string: ["localhost","127.0.0.1","192.168.1.63"]
        - Comma-separated:  localhost,127.0.0.1,192.168.1.63
        """
        if v is None or (isinstance(v, str) and not v.strip()):
            # Explicit empty env should fall back to the Field default.
            default = cls.model_fields["ALLOWED_HOSTS"].default
            return list(default) if isinstance(default, list) else default
        return cls._parse_list_env(v, field_name="ALLOWED_HOSTS")

    @field_validator("ALERT_EMAIL_RECIPIENTS", mode="before")
    @classmethod
    def parse_alert_email_recipients(cls, v):
        """Parse alert email recipients from env (comma-separated or JSON list)."""
        if v is None or (isinstance(v, str) and not v.strip()):
            return []
        return cls._parse_list_env(v, field_name="ALERT_EMAIL_RECIPIENTS")

    @classmethod
    def _parse_list_env(cls, v, *, field_name: str) -> List[str]:
        """
        Parse list-like environment variable values.

        Accepts:
        - JSON list strings: ["a","b"]
        - Comma-separated strings: a,b
        - Python lists/tuples/sets
        """
        if isinstance(v, str):
            s = v.strip()
            if s.startswith("["):
                try:
                    parsed = json.loads(s)
                except json.JSONDecodeError as e:
                    raise ValueError(
                        f"{field_name} must be a JSON list or comma-separated string; "
                        f"got invalid JSON: {v!r}"
                    ) from e
                if not isinstance(parsed, list):
                    raise ValueError(f"{field_name} must be a JSON list; got {type(parsed).__name__}")
                items = parsed
            else:
                items = [part.strip() for part in s.split(",")]
        elif isinstance(v, (list, tuple, set)):
            items = list(v)
        else:
            raise ValueError(
                f"{field_name} must be a JSON list string, comma-separated string, or list; "
                f"got {type(v).__name__}"
            )

        cleaned = [str(item).strip() for item in items if str(item).strip()]
        if not cleaned:
            default = cls.model_fields[field_name].default
            return list(default) if isinstance(default, list) else default
        return cleaned

    @field_validator("SECRET_KEY", mode="after")
    @classmethod
    def reject_weak_secret_key(cls, v: str) -> str:
        """Prevent startup with placeholder or weak secret keys."""
        weak_keys = {
            "change-this-to-a-random-secret-key-min-32-chars",
            "change-this-secret-key-in-production",
            "secret",
            "changeme",
        }
        if v in weak_keys or len(v) < 32:
            raise ValueError(
                "SECRET_KEY is insecure. Set a random string of at least 32 characters. "
                "Generate one with: python -c \"import secrets; print(secrets.token_urlsafe(48))\""
            )
        return v

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore"
    )


# Global settings instance
settings = Settings()
