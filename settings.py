import yaml
from pathlib import Path
from typing import List
from pydantic_settings import BaseSettings

BASE_DIR = Path(__file__).parent
CONFIG_FILE = BASE_DIR / "config.yaml"
# relative paths in config.yaml are relative to the repo, so the agent works from any directory (e.g. cron)
PATH_FIELDS = ("prompt_file", "agent_state_file", "querylog_cache_file", "log_file", "rules_backup_dir")


class Settings(BaseSettings):
    adguard_base_url: str
    adguard_querylog: str
    adguard_username: str
    adguard_password: str
    adguard_query_limit: int  # page size; pages are fetched back to the last run or the window start
    adguard_max_queries: int
    querylog_window_days: int
    querylog_cache_file: str
    adguard_timeout: int
    openai_api_key: str
    model: str
    history_limit: int
    prompt_file: str
    agent_state_file: str
    log_level: str
    trusted_domains: List[str]
    suspicious_keywords: List[str]
    suspicious_tlds: List[str]
    filter_out_keywords: List[str]
    device_names: dict[str, str]
    no_parent_block_domains: List[str]
    protected_vendor_domains: List[str]
    never_block_keywords: List[str]
    rules_backup_dir: str
    rules_backup_keep: int
    revert_sibling_depth: int
    retry_storm_min_blocked: int
    clients_per_domain: int
    keep_blocked_domains: List[str]
    router_ssh_jump: str
    router_ssh_host: str
    router_timeout: int
    junk_suffixes: List[str]
    confidence_high: float
    confidence_medium: float
    dga_min_label_len: int
    dga_entropy_threshold: float
    family_min_size: int
    family_hex_min_len: int
    domain_stats_retention_days: int
    reflections_limit: int
    log_file: str
    log_rotation: str
    log_retention: int


def load_settings() -> Settings:
    if not CONFIG_FILE.exists():
        raise FileNotFoundError(f"{CONFIG_FILE} not found")
    with open(CONFIG_FILE) as f:
        loaded = Settings(**yaml.safe_load(f))
    for field in PATH_FIELDS:
        setattr(loaded, field, str(BASE_DIR / getattr(loaded, field)))
    return loaded


settings = load_settings()
