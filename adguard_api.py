import requests
from colorama import Fore, Style
from loguru import logger

from settings import settings


def get_custom_blocked_domains() -> set[str]:
    """Get domains from AdGuard custom filtering rules"""
    auth: tuple[str, str | None] | None = None
    if settings.adguard_username and settings.adguard_password:
        auth = (settings.adguard_username, settings.adguard_password)

    try:
        r = requests.get(f"{settings.adguard_base_url}/control/filtering/status", auth=auth, timeout=settings.adguard_timeout)
        r.raise_for_status()
        data = r.json()

        user_rules = data.get("user_rules", [])

        blocked = set()
        for rule in user_rules:
            if rule.startswith("||") and rule.endswith("^"):
                domain = rule[2:-1]
                blocked.add(domain)

        logger.info(f"Loaded {len(blocked)} custom rules for blocked domains from AdGuard")

        if blocked:
            print(f"\n{'=' * 100}")
            print(f"{Style.BRIGHT}{Fore.CYAN}ALREADY BLOCKED IN ADGUARD ({len(blocked)} domains){Style.RESET_ALL}")
            print(f"{'=' * 100}")
            for domain in sorted(blocked):
                print(f"  {Fore.CYAN}{domain}{Style.RESET_ALL}")
            print(f"{'=' * 100}\n")

        return blocked
    except Exception as e:
        logger.error(f"Could not fetch custom blocked domains from AdGuard: {e}")
        return set()


def block_domain_in_adguard(domain: str, reason: str = "") -> bool:
    """Block domain in AdGuard by adding custom filtering rule with comment"""
    auth: tuple[str, str | None] | None = None
    if settings.adguard_username and settings.adguard_password:
        auth = (settings.adguard_username, settings.adguard_password)

    try:
        from datetime import datetime

        r = requests.get(f"{settings.adguard_base_url}/control/filtering/status", auth=auth, timeout=settings.adguard_timeout)
        r.raise_for_status()
        data = r.json()

        user_rules = data.get("user_rules", [])
        new_rule = f"||{domain}^"

        if new_rule in user_rules:
            logger.info(f"Domain {domain} already blocked")
            return True

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")
        reason_short = reason[:60] if reason else "Agent blocked"
        comment = f"! {timestamp} | {reason_short}"

        user_rules.append(comment)
        user_rules.append(new_rule)

        r = requests.post(f"{settings.adguard_base_url}/control/filtering/set_rules", auth=auth, json={"rules": user_rules}, timeout=settings.adguard_timeout)
        r.raise_for_status()
        logger.success(f"Blocked domain: {domain}")
        return True
    except Exception as e:
        logger.error(f"Failed to block domain {domain}: {e}")
        return False


def unblock_domain_in_adguard(domain: str) -> bool:
    """Unblock domain in AdGuard by removing custom filtering rule"""
    auth: tuple[str, str | None] | None = None
    if settings.adguard_username and settings.adguard_password:
        auth = (settings.adguard_username, settings.adguard_password)

    try:
        r = requests.get(f"{settings.adguard_base_url}/control/filtering/status", auth=auth, timeout=settings.adguard_timeout)
        r.raise_for_status()
        data = r.json()

        user_rules = data.get("user_rules", [])
        rule_to_remove = f"||{domain}^"

        if rule_to_remove not in user_rules:
            logger.warning(f"Domain {domain} not in blocked list")
            return False

        user_rules.remove(rule_to_remove)

        r = requests.post(f"{settings.adguard_base_url}/control/filtering/set_rules", auth=auth, json={"rules": user_rules}, timeout=settings.adguard_timeout)
        r.raise_for_status()
        logger.success(f"Unblocked domain: {domain}")
        return True
    except Exception as e:
        logger.error(f"Failed to unblock domain {domain}: {e}")
        return False


def fetch_adguard_logs() -> dict:
    """Fetch query logs from AdGuard"""
    auth: tuple[str, str | None] | None = None
    if settings.adguard_username and settings.adguard_password:
        auth = (settings.adguard_username, settings.adguard_password)

    r = requests.get(
        f"{settings.adguard_base_url}{settings.adguard_querylog}", auth=auth, params={"limit": settings.adguard_query_limit}, timeout=settings.adguard_timeout
    )
    r.raise_for_status()
    return r.json()
