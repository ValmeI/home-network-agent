from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    adguard_url: str
    adguard_username: str
    adguard_password: str
    adguard_query_limit: int
    adguard_timeout: int
    openai_api_key: str
    model: str
    history_limit: int
    log_file: str
    prompt_file: str
    log_level: str

    # Domain filtering patterns
    trusted_domains: List[str] = [
        "github.com",
        "githubusercontent.com",
        "microsoft.com",
        "msftncsi.com",
        "apple.com",
        "gstatic.com",
        "googleapis.com",
        "cloudflare.com",
        "akamai.net",
        "gitkraken.com",
        "synology.com",
        "plex.tv",
        "dropboxapi.com",
        "spaceship.dev",
        "qdrant.io",
        "tailscale.io",
    ]

    suspicious_keywords: List[str] = ["telemetry", "analytics", "metric", "track", "pixel", "beacon", "ads", "doubleclick"]

    min_frequency_trusted: int = 30  # Minimum query count to consider a domain as "actively used"


settings = Settings()
