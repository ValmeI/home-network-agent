import json
from datetime import date, datetime, timedelta

from loguru import logger

from network_analyzer import is_covered
from settings import settings


def load_agent_state() -> dict:
    """Load agent state from file or initialize default state"""
    try:
        with open(settings.agent_state_file) as f:
            return _prune_domain_stats(json.load(f))
    except FileNotFoundError:
        logger.info("No agent state found, initializing default state")
        default_state = {
            "agent_meta": {"name": "home-network-agent", "version": "0.1", "started_at": datetime.now().isoformat()},
            "goal": {"primary": "Reduce unwanted tracking while minimizing service breakage"},
            "memory": {"history": [], "stats": {"total_decisions": 0, "reverts": 0}, "domain_stats": {}, "reflections": []},
            "last_decision": {},
        }
        save_agent_state(default_state)
        return default_state


def save_agent_state(state: dict) -> None:
    """Save agent state to file"""
    with open(settings.agent_state_file, "w") as f:
        json.dump(state, f, indent=2)


def _bump(state: dict, domain: str, key: str) -> None:
    entry = state["memory"]["domain_stats"].setdefault(domain, {})
    entry[key] = entry.get(key, 0) + 1
    entry["last"] = date.today().isoformat()


def _prune_domain_stats(state: dict) -> dict:
    """Per-domain aggregate; entries not seen within the retention window are dropped, reverts never"""
    memory = state["memory"]
    cutoff = (date.today() - timedelta(days=settings.domain_stats_retention_days)).isoformat()
    kept = {d: e for d, e in memory["domain_stats"].items() if e["last"] >= cutoff or e.get("reverted")}
    if len(kept) < len(memory["domain_stats"]):
        logger.info(f"Pruned {len(memory['domain_stats']) - len(kept)} domain stats not seen since {cutoff}")
    memory["domain_stats"] = kept
    return state


def skipped_domains(state: dict) -> set[str]:
    return {domain for domain, entry in state["memory"]["domain_stats"].items() if entry.get("skipped")}


def reverted_domains(state: dict) -> set[str]:
    """Reverts are kept forever - a block the user undid must never be offered again"""
    return {domain for domain, entry in state["memory"]["domain_stats"].items() if entry.get("reverted")}


def update_agent_state_with_decision(state: dict, summary: dict, decision: dict, blocked: list[str]) -> dict:
    """Record a run; block recommendations the user did not block count as skipped"""
    timestamp = datetime.now().isoformat()

    state["last_decision"] = {
        "observations": {
            "total_queries": summary["total_queries"],
            "unique_domains": summary["unique_domains"],
            "review_domains_count": len(summary["domain_counts"]),
            "suspicious_domains_count": len(summary["suspicious_domains"]),
            "blocked_count": summary["blocked_count"],
        },
        "decision": {
            "status": decision.get("decision", "N/A"),
            "reason": decision.get("reason", "N/A"),
            "domains_to_block": decision.get("domains_to_block", []),
            "domains_to_watch": decision.get("domains_to_watch", []),
            "domains_to_allow": decision.get("domains_to_allow", []),
            "blocked": blocked,
        },
        "timestamp": timestamp,
    }
    state["memory"]["history"].append(state["last_decision"])

    for key, action in (("domains_to_block", "recommended"), ("domains_to_watch", "watched")):
        for item in decision[key]:
            domain = item["domain"]
            _bump(state, domain, action)
            if action == "recommended" and not is_covered(domain, blocked):
                _bump(state, domain, "skipped")

    for domain in blocked:
        _bump(state, domain, "blocked")

    stats = state["memory"]["stats"]
    stats["total_decisions"] += 1

    state["memory"]["history"] = state["memory"]["history"][-settings.history_limit :]

    return state


def record_revert(domain: str, reason: str) -> None:
    """Record a domain revert in agent state"""
    state = load_agent_state()
    timestamp = datetime.now().isoformat()

    _bump(state, domain, "reverted")

    state["memory"]["stats"]["reverts"] += 1

    if "reflections" not in state["memory"]:
        state["memory"]["reflections"] = []

    reflection = {"timestamp": timestamp, "domain": domain, "lesson": f"Blocking {domain} was a mistake: {reason}"}
    state["memory"]["reflections"].append(reflection)

    if len(state["memory"]["reflections"]) > settings.reflections_limit:
        state["memory"]["reflections"] = state["memory"]["reflections"][-settings.reflections_limit :]

    save_agent_state(state)
    logger.success(f"Domain {domain} revert recorded and lesson learned")
    logger.info(f"Total reverts: {state['memory']['stats']['reverts']}")
