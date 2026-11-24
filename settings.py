from pathlib import Path
from typing import Any

import yaml
from pydantic_settings import BaseSettings


BASE_DIR = Path(__file__).parent
CONFIG_FILE = BASE_DIR / "config.yaml"
PRIVATE_FILE = BASE_DIR / "private.yaml"  # credentials and personal domains, not in git
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
    trusted_domains: list[str]
    suspicious_keywords: list[str]
    suspicious_tlds: list[str]
    filter_out_keywords: list[str]
    device_names: dict[str, str]
    no_parent_block_domains: list[str]
    protected_vendor_domains: list[str]
    never_block_keywords: list[str]
    rules_backup_dir: str
    rules_backup_keep: int
    revert_sibling_depth: int
    retry_storm_min_blocked: int
    clients_per_domain: int
    keep_blocked_domains: list[str]
    router_ssh_jump: str
    router_ssh_host: str
    router_timeout: int
    junk_suffixes: list[str]
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


def _read_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"{path} not found")
    with open(path) as f:
        return yaml.safe_load(f)


def merge_private(shared: dict[str, Any], private: dict[str, Any]) -> dict[str, Any]:
    """Lists in both files are joined; any other key may be set in only one file"""
    merged = dict(shared)
    for key, value in private.items():
        if key not in shared:
            merged[key] = value
        elif isinstance(shared[key], list) and isinstance(value, list):
            merged[key] = shared[key] + value
        else:
            raise ValueError(f"{key} is set in both {CONFIG_FILE.name} and {PRIVATE_FILE.name}; keep it in one")
    return merged


def load_settings() -> Settings:
    loaded = Settings(**merge_private(_read_yaml(CONFIG_FILE), _read_yaml(PRIVATE_FILE)))
    for field in PATH_FIELDS:
        setattr(loaded, field, str(BASE_DIR / getattr(loaded, field)))
    return loaded


settings = load_settings()
