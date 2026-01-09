import yaml
from pathlib import Path
from typing import List
from pydantic import BaseModel

CONFIG_FILE = "config.yaml"


class Settings(BaseModel):
    adguard_base_url: str
    adguard_querylog: str
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
    trusted_domains: List[str]
    suspicious_keywords: List[str]
    filter_out_keywords: List[str]
    min_frequency_trusted: int


def load_settings() -> Settings:
    config_file = Path(CONFIG_FILE)
    if not config_file.exists():
        raise FileNotFoundError(f"{CONFIG_FILE} not found")

    with open(config_file) as f:
        config_data = yaml.safe_load(f)

    return Settings(**config_data)


settings = load_settings()
