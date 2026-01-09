import json
import sys
from collections import Counter
from datetime import datetime

import requests
from colorama import Fore, Style, init as colorama_init
from loguru import logger
from openai import OpenAI

from logging_config import init_logging
from settings import settings

colorama_init(autoreset=True)
init_logging(settings.log_level)
client = OpenAI(api_key=settings.openai_api_key)


def load_history() -> list[dict]:
    try:
        with open(settings.log_file) as f:
            return [json.loads(l) for l in f]
    except FileNotFoundError:
        return []


def get_seen_domains() -> set[str]:
    """Get all domains from previous decisions"""
    history = load_history()
    return {str(d["domain"]) for d in history if "domain" in d and d["domain"]}


def get_custom_blocked_domains() -> set[str]:
    """Get domains from AdGuard custom filtering rules"""
    auth: tuple[str, str | None] | None = None
    if settings.adguard_username and settings.adguard_password:
        auth = (settings.adguard_username, settings.adguard_password)
    
    try:
        base_url = settings.adguard_url.replace("/control/querylog", "")
        r = requests.get(f"{base_url}/control/filtering/status", auth=auth, timeout=settings.adguard_timeout)
        r.raise_for_status()
        data = r.json()
        
        user_rules = data.get("user_rules", [])
        
        blocked = set()
        for rule in user_rules:
            if rule.startswith("||") and rule.endswith("^"):
                domain = rule[2:-1]
                blocked.add(domain)
        
        logger.info(f"Loaded {len(blocked)} custom blocked domains from AdGuard")
        return blocked
    except Exception as e:
        logger.error(f"Could not fetch custom blocked domains from AdGuard: {e}")
        return set()


def _extract_domain_clients(queries: list[dict]) -> dict[str, Counter]:
    domain_clients = {}
    for q in queries:
        domain = q.get("question", {}).get("name", "")
        if not domain:
            continue

        client_info = q.get("client_info", {})
        client_name = client_info.get("name", "") or q.get("client", "unknown")

        if domain not in domain_clients:
            domain_clients[domain] = Counter()
        domain_clients[domain][client_name] += 1
    
    return domain_clients


def _find_suspicious_domains(domains: set[str], counts: Counter, custom_blocked: set[str]) -> list[str]:
    suspicious = []
    for domain in domains:
        if domain in custom_blocked:
            continue
            
        lower = domain.lower()
        count = counts[domain]

        is_trusted = any(pattern in lower for pattern in settings.trusted_domains)
        if is_trusted and count >= settings.min_frequency_trusted:
            continue

        if any(x in lower for x in settings.suspicious_keywords):
            suspicious.append(domain)
    
    return suspicious


def summarize(log: dict, custom_blocked: set[str]) -> dict:
    queries = log.get("data", [])
    if not queries:
        return {"error": "No queries found"}

    allowed_queries = [q for q in queries if not q.get("reason", "").startswith("Filtered")]
    domains = [q.get("question", {}).get("name", "") for q in allowed_queries if "question" in q]
    domains = [d for d in domains if d and "4days" not in d.lower()]

    blocked_count = len(queries) - len(allowed_queries)
    counts = Counter(domains)
    
    seen = get_seen_domains()
    new_domains = [d for d in set(domains) if d not in seen and d not in custom_blocked]
    
    domain_clients = _extract_domain_clients(allowed_queries)
    suspicious = _find_suspicious_domains(set(domains), counts, custom_blocked)

    hour = datetime.now().hour
    is_night = hour < 6 or hour > 23

    return {
        "top_domains": counts.most_common(5),
        "total_queries": len(domains),
        "unique_domains": len(set(domains)),
        "new_domains": new_domains[:10],
        "suspicious_domains": suspicious[:10],
        "blocked_count": blocked_count,
        "time_context": f"Hour {hour}, {'night' if is_night else 'day'}",
        "domain_clients": {domain: dict(clients.most_common(5)) for domain, clients in domain_clients.items() if (domain in suspicious or domain in new_domains) and domain not in custom_blocked},
    }


def fetch_adguard_logs() -> dict:
    auth: tuple[str, str | None] | None = None
    if settings.adguard_username and settings.adguard_password:
        auth = (settings.adguard_username, settings.adguard_password)

    r = requests.get(settings.adguard_url, auth=auth, params={"limit": settings.adguard_query_limit}, timeout=settings.adguard_timeout)
    r.raise_for_status()
    return r.json()


def analyze_with_llm(summary: dict, history: list[dict], custom_blocked: set[str]) -> dict:
    try:
        with open(settings.prompt_file) as f:
            prompt_template = f.read()
    except FileNotFoundError:
        logger.error(f"Prompt file not found: {settings.prompt_file}")
        raise

    user_message = (
        f"CURRENT STATS:\n{json.dumps(summary, indent=2)}\n\n"
        f"PREVIOUS DECISIONS:\n{json.dumps(history, indent=2)}\n\n"
        f"TRUSTED DOMAINS (should be ALLOW unless clearly malicious):\n{json.dumps(settings.trusted_domains, indent=2)}\n\n"
        f"ALREADY BLOCKED IN ADGUARD (do NOT include in WATCH or BLOCK lists):\n{json.dumps(sorted(custom_blocked), indent=2)}\n\n"
        "Analyze the current network activity and decide on the overall threat level or notable patterns."
    )

    resp = client.chat.completions.create(
        model=settings.model,
        messages=[{"role": "system", "content": prompt_template}, {"role": "user", "content": user_message}],
        response_format={"type": "json_object"},
    )

    if not resp.choices[0].message.content:
        raise ValueError("Empty response from LLM")

    decision = json.loads(resp.choices[0].message.content)
    decision["ts"] = datetime.now().isoformat()
    decision["summary"] = {
        "total_queries": summary["total_queries"],
        "new_domains_count": len(summary["new_domains"]),
        "top_domain": summary["top_domains"][0] if summary["top_domains"] else None,
        "domain_clients": summary.get("domain_clients", {}),
    }
    return decision


def save_decision(decision: dict) -> None:
    with open(settings.log_file, "a") as f:
        f.write(json.dumps(decision) + "\n")


def _format_clients(clients: dict) -> str:
    if not clients:
        return ""
    total = sum(clients.values())
    parts = [f"{name}: {count}q" for name, count in clients.items()]
    return f" ({', '.join(parts)}; total: {total}q)"


def log_decision_results(decision: dict) -> None:
    logger.success("Decision made")
    
    status = decision.get('decision', 'N/A')
    status_colors = {
        "ALLOW": Fore.GREEN,
        "WATCH": Fore.YELLOW,
        "ALERT": Fore.RED,
    }
    color = status_colors.get(status, Fore.WHITE)
    print(f"{Style.BRIGHT}Status: {color}{status}{Style.RESET_ALL}")
    
    logger.info(f"Reason: {decision.get('reason', 'N/A')}")

    domains_to_block = decision.get("domains_to_block", [])
    domains_to_watch = decision.get("domains_to_watch", [])
    domains_to_allow = decision.get("domains_to_allow", [])
    explanation = decision.get("explanation", {})
    domain_clients = decision.get("summary", {}).get("domain_clients", {})

    if isinstance(explanation, str):
        explanation = {}

    if domains_to_allow:
        logger.success(f"\nSafe to ALLOW ({len(domains_to_allow)} domains):")
        for domain in domains_to_allow:
            reason = explanation.get(domain, "No reason provided")
            clients_info = _format_clients(domain_clients.get(domain, {}))
            print(f"  {Style.BRIGHT}{Fore.GREEN}{domain}{Style.RESET_ALL} {Style.DIM}{clients_info}{Style.RESET_ALL}")
            print(f"    {Style.DIM}{reason}{Style.RESET_ALL}")

    if domains_to_watch:
        logger.info(f"\nWatching ({len(domains_to_watch)} domains):")
        for domain in domains_to_watch:
            reason = explanation.get(domain, "No reason provided")
            clients_info = _format_clients(domain_clients.get(domain, {}))
            print(f"  {Style.BRIGHT}{Fore.YELLOW}{domain}{Style.RESET_ALL} {Style.DIM}{clients_info}{Style.RESET_ALL}")
            print(f"    {Style.DIM}{reason}{Style.RESET_ALL}")

    if domains_to_block:
        logger.warning(f"\nRecommended to BLOCK ({len(domains_to_block)} domains):")
        for domain in domains_to_block:
            reason = explanation.get(domain, "No reason provided")
            clients_info = _format_clients(domain_clients.get(domain, {}))
            print(f"  {Style.BRIGHT}{Fore.RED}{domain}{Style.RESET_ALL} {Style.DIM}{clients_info}{Style.RESET_ALL}")
            print(f"    {Style.DIM}{reason}{Style.RESET_ALL}")


def _filter_history(history: list[dict], custom_blocked: set[str]) -> list[dict]:
    filtered_history = []
    for decision in history:
        filtered_decision = decision.copy()
        if "domains_to_watch" in filtered_decision:
            filtered_decision["domains_to_watch"] = [d for d in filtered_decision["domains_to_watch"] if d not in custom_blocked and "4days" not in d.lower()]
        if "domains_to_block" in filtered_decision:
            filtered_decision["domains_to_block"] = [d for d in filtered_decision["domains_to_block"] if d not in custom_blocked and "4days" not in d.lower()]
        if "domains_to_allow" in filtered_decision:
            filtered_decision["domains_to_allow"] = [d for d in filtered_decision["domains_to_allow"] if d not in custom_blocked and "4days" not in d.lower()]
        filtered_history.append(filtered_decision)
    return filtered_history


def main() -> None:
    try:
        logger.info("Fetching AdGuard query log...")
        log = fetch_adguard_logs()
        
        custom_blocked = get_custom_blocked_domains()

        logger.info("Analyzing network activity...")
        summary = summarize(log, custom_blocked)
        logger.info(f"Suspicious domains found: {len(summary.get('suspicious_domains', []))}")

        if "error" in summary:
            logger.error(summary["error"])
            sys.exit(1)

        logger.info(f"Total queries: {summary['total_queries']}")
        logger.info(f"Unique domains: {summary['unique_domains']}")
        logger.info(f"New domains: {len(summary['new_domains'])}")
        logger.info(f"Already blocked by AdGuard: {summary['blocked_count']}")

        history = load_history()[-settings.history_limit :]
        filtered_history = _filter_history(history, custom_blocked)

        logger.info("Agent reasoning...")
        decision = analyze_with_llm(summary, filtered_history, custom_blocked)

        save_decision(decision)
        log_decision_results(decision)

    except requests.RequestException as e:
        logger.error(f"Network error: {e}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        logger.error(f"JSON parsing error: {e}")
        sys.exit(1)
    except Exception as e:
        logger.exception("Unexpected error")
        sys.exit(1)


if __name__ == "__main__":
    main()
