from functools import lru_cache
from pathlib import Path
from typing import Annotated, Literal

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "CyberLens"
    app_mode: Literal["demo", "live"] = "live"
    log_level: str = "INFO"
    api_cors_origins: Annotated[list[str], NoDecode] = []
    database_url: str = "postgresql+psycopg://cyberlens:cyberlens@localhost:5432/cyberlens"
    redis_url: str = "redis://localhost:6379/0"
    redis_password: str | None = None
    bootstrap_admin_username: str = "admin"
    bootstrap_admin_password: str | None = None
    # Local Demo tests and workflows may use plain HTTP. The validator below
    # rejects this default outside Demo; Live Compose explicitly sets true.
    cookie_secure: bool = False
    hibp_api_key: str | None = None
    virustotal_api_key: str | None = None
    nvd_api_key: str | None = None
    # Community XposedOrNot use is opt-in and limited by its published free-tier terms.
    xposedornot_enabled: bool = False
    xposedornot_community_use_ack: bool = False
    xposedornot_cache_key: str | None = None
    xposedornot_cache_ttl_seconds: int = 900
    collector_timeout_seconds: float = 8.0
    spamhaus_drop_enabled: bool = True
    spamhaus_drop_refresh_interval_hours: int = 24
    spamhaus_drop_freshness_hours: int = 48
    spamhaus_drop_max_download_bytes: int = 1_000_000
    cins_army_enabled: bool = True
    cins_army_refresh_interval_hours: int = 24
    cins_army_freshness_hours: int = 48
    cins_army_max_download_bytes: int = 2_000_000
    # OpenPhish Community Feed is disabled unless the operator has confirmed
    # an applicable permitted use. Acknowledgements do not grant provider rights.
    openphish_enabled: bool = False
    openphish_use_ack: bool = False
    openphish_personal_owner_username: str | None = None
    openphish_provider_sharing_permission_ack: bool = False
    openphish_refresh_interval_hours: int = 12
    openphish_freshness_hours: int = 24
    openphish_max_download_bytes: int = 2_000_000

    model_config = SettingsConfigDict(
        env_file=Path(__file__).resolve().parents[2] / ".env",
        case_sensitive=False,
        extra="ignore",
    )

    @field_validator("api_cors_origins", mode="before")
    @classmethod
    def parse_origins(cls, value: object) -> object:
        if isinstance(value, str):
            return [origin.strip() for origin in value.split(",") if origin.strip()]
        return value

    @field_validator("spamhaus_drop_refresh_interval_hours")
    @classmethod
    def enforce_spamhaus_daily_cooldown(cls, value: int) -> int:
        # Spamhaus asks users not to download the data more than once per day.
        if value < 24 or value > 720:
            raise ValueError("SPAMHAUS_DROP_REFRESH_INTERVAL_HOURS must be between 24 and 720")
        return value

    @field_validator("spamhaus_drop_freshness_hours")
    @classmethod
    def validate_spamhaus_freshness(cls, value: int) -> int:
        if value < 1 or value > 720:
            raise ValueError("SPAMHAUS_DROP_FRESHNESS_HOURS must be between 1 and 720")
        return value

    @field_validator("spamhaus_drop_max_download_bytes")
    @classmethod
    def validate_spamhaus_download_limit(cls, value: int) -> int:
        if value < 1024 or value > 10_000_000:
            raise ValueError("SPAMHAUS_DROP_MAX_DOWNLOAD_BYTES must be between 1024 and 10000000")
        return value

    @field_validator("cins_army_refresh_interval_hours")
    @classmethod
    def validate_cins_army_refresh_interval(cls, value: int) -> int:
        # This is CyberLens's conservative local schedule; it makes no claim
        # about how frequently CINS publishes updates.
        if value < 24 or value > 720:
            raise ValueError("CINS_ARMY_REFRESH_INTERVAL_HOURS must be between 24 and 720")
        return value

    @field_validator("cins_army_freshness_hours")
    @classmethod
    def validate_cins_army_freshness(cls, value: int) -> int:
        if value < 1 or value > 720:
            raise ValueError("CINS_ARMY_FRESHNESS_HOURS must be between 1 and 720")
        return value

    @field_validator("cins_army_max_download_bytes")
    @classmethod
    def validate_cins_army_download_limit(cls, value: int) -> int:
        if value < 1024 or value > 10_000_000:
            raise ValueError("CINS_ARMY_MAX_DOWNLOAD_BYTES must be between 1024 and 10000000")
        return value

    @field_validator("openphish_refresh_interval_hours")
    @classmethod
    def validate_openphish_refresh_interval(cls, value: int) -> int:
        # This is CyberLens's local conservative refresh interval, not a
        # statement about provider publication frequency.
        if value < 12 or value > 720:
            raise ValueError("OPENPHISH_REFRESH_INTERVAL_HOURS must be between 12 and 720")
        return value

    @field_validator("openphish_freshness_hours")
    @classmethod
    def validate_openphish_freshness(cls, value: int) -> int:
        if value < 1 or value > 720:
            raise ValueError("OPENPHISH_FRESHNESS_HOURS must be between 1 and 720")
        return value

    @field_validator("openphish_max_download_bytes")
    @classmethod
    def validate_openphish_download_limit(cls, value: int) -> int:
        if value < 1024 or value > 10_000_000:
            raise ValueError("OPENPHISH_MAX_DOWNLOAD_BYTES must be between 1024 and 10000000")
        return value

    @model_validator(mode="after")
    def validate_live_secrets(self) -> "Settings":
        """Fail closed for the settings that would otherwise use published defaults.

        Demo mode deliberately keeps the one-command local workflow.  Live mode
        requires operators to provide their own database/Redis credentials and
        to use secure cookies; the first administrator password is validated by
        the bootstrap command only when an administrator does not yet exist.
        """
        if self.app_mode != "live":
            return self
        if not self.cookie_secure:
            raise ValueError("COOKIE_SECURE must be true outside Demo mode")
        database_password = ""
        try:
            from urllib.parse import urlparse

            database_password = urlparse(self.database_url).password or ""
        except ValueError:
            pass
        if database_password in {"", "cyberlens"}:
            raise ValueError("DATABASE_URL must use a non-default password outside Demo mode")
        # A password embedded in REDIS_URL is accepted for deployments that
        # already manage the URL as one secret.
        try:
            from urllib.parse import urlparse

            redis_password = urlparse(self.redis_url).password
        except ValueError:
            redis_password = None
        if not (self.redis_password or redis_password):
            raise ValueError("REDIS_PASSWORD or a password-bearing REDIS_URL is required outside Demo mode")
        if self.xposedornot_enabled:
            if not self.xposedornot_community_use_ack:
                raise ValueError("XPOSEDORNOT_COMMUNITY_USE_ACK must be true when XPOSEDORNOT_ENABLED is true")
            if not self.xposedornot_cache_key:
                raise ValueError("XPOSEDORNOT_CACHE_KEY is required when XPOSEDORNOT_ENABLED is true")
            try:
                from cryptography.fernet import Fernet

                Fernet(self.xposedornot_cache_key.encode("ascii"))
            except (ValueError, UnicodeError, TypeError):
                raise ValueError("XPOSEDORNOT_CACHE_KEY must be a valid Fernet key") from None
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
