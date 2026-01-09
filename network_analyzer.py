from collections import Counter
from datetime import datetime

from agent_state import get_seen_domains
from settings import settings


def _should_filter_out(domain: str) -> bool:
    for keyword in settings.filter_out_keywords:
        if keyword in domain.lower():
            return True
    return False


def _extract_domain_string(item) -> str | None:
    """Extract domain string from either a string or dict format"""
    if isinstance(item, dict):
        return item.get("domain")
    return item if isinstance(item, str) else None


def _filter_domains(domains: list, custom_blocked: set[str]) -> list:
    """Filter domains, handling both string and dict formats"""
    filtered = []
    for item in domains:
        domain = _extract_domain_string(item)
        if domain and domain not in custom_blocked and not _should_filter_out(domain):
            filtered.append(item)
    return filtered


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
    """Analyze network queries and return summary"""
    queries = log.get("data", [])
    if not queries:
        return {"error": "No queries found"}

    allowed_queries = [q for q in queries if not q.get("reason", "").startswith("Filtered")]
    domains = [q.get("question", {}).get("name", "") for q in allowed_queries if "question" in q]
    domains = [d for d in domains if d and not _should_filter_out(d)]

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
        "domain_clients": {
            domain: dict(clients.most_common(5))
            for domain, clients in domain_clients.items()
            if (domain in suspicious or domain in new_domains) and domain not in custom_blocked
        },
    }


def filter_history(history: list[dict], custom_blocked: set[str]) -> list[dict]:
    """Filter history to remove already blocked domains"""
    filtered_history = []
    for entry in history:
        filtered_entry = entry.copy()
        decision = entry.get("decision", {})
        if decision:
            filtered_decision = decision.copy()
            if "domains_to_watch" in filtered_decision:
                filtered_decision["domains_to_watch"] = _filter_domains(filtered_decision["domains_to_watch"], custom_blocked)
            if "domains_to_block" in filtered_decision:
                filtered_decision["domains_to_block"] = _filter_domains(filtered_decision["domains_to_block"], custom_blocked)
            if "domains_to_allow" in filtered_decision:
                filtered_decision["domains_to_allow"] = _filter_domains(filtered_decision["domains_to_allow"], custom_blocked)
            filtered_entry["decision"] = filtered_decision
        filtered_history.append(filtered_entry)
    return filtered_history
