import json
from datetime import datetime

from loguru import logger

from settings import settings


def _extract_domain_string(item) -> str | None:
    """Extract domain string from either a string or dict format"""
    if isinstance(item, dict):
        return item.get("domain")
    return item if isinstance(item, str) else None


def load_agent_state() -> dict:
    """Load agent state from file or initialize default state"""
    try:
        with open(settings.agent_state_file) as f:
            return json.load(f)
    except FileNotFoundError:
        logger.info("No agent state found, initializing default state")
        default_state = {
            "agent_meta": {"name": "home-network-agent", "version": "0.1", "started_at": datetime.now().isoformat()},
            "goal": {
                "primary": "Reduce unwanted tracking while minimizing service breakage",
                "constraints": ["Avoid blocking essential services", "Prefer reversible actions", "Require confidence >= 0.7 for auto-action"],
            },
            "memory": {
                "history": [],
                "stats": {"total_decisions": 0, "auto_actions": 0, "manual_confirmations": 0, "reverts": 0},
                "domain_history": {},
                "reflections": [],
            },
            "last_decision": {},
        }
        save_agent_state(default_state)
        return default_state


def save_agent_state(state: dict) -> None:
    """Save agent state to file"""
    with open(settings.agent_state_file, "w") as f:
        json.dump(state, f, indent=2)


def load_history() -> list[dict]:
    """Get history from agent state"""
    state = load_agent_state()
    return state.get("memory", {}).get("history", [])


def get_seen_domains() -> set[str]:
    """Get all domains from previous decisions"""
    history = load_history()
    seen = set()
    for entry in history:
        decision = entry.get("decision", {})
        for domain_list_key in ["domains_to_block", "domains_to_watch", "domains_to_allow"]:
            for item in decision.get(domain_list_key, []):
                domain = _extract_domain_string(item)
                if domain:
                    seen.add(domain)
    return seen


def update_agent_state_with_decision(state: dict, summary: dict, decision: dict, auto_blocked: list[str]) -> dict:
    """Update agent state with new decision and observations"""
    timestamp = datetime.now().isoformat()

    state["last_decision"] = {
        "observations": {
            "total_queries": summary["total_queries"],
            "unique_domains": summary["unique_domains"],
            "new_domains_count": len(summary["new_domains"]),
            "suspicious_domains_count": len(summary.get("suspicious_domains", [])),
            "blocked_count": summary["blocked_count"],
            "time_context": summary["time_context"],
        },
        "decision": {
            "status": decision.get("decision", "N/A"),
            "reason": decision.get("reason", "N/A"),
            "domains_to_block": decision.get("domains_to_block", []),
            "domains_to_watch": decision.get("domains_to_watch", []),
            "domains_to_allow": decision.get("domains_to_allow", []),
            "auto_blocked": auto_blocked,
        },
        "timestamp": timestamp,
    }

    history_entry = {"timestamp": timestamp, "observations": state["last_decision"]["observations"], "decision": state["last_decision"]["decision"]}
    state["memory"]["history"].append(history_entry)

    if "domain_history" not in state["memory"]:
        state["memory"]["domain_history"] = {}

    domains_from_decision = decision.get("domains_to_block", [])
    for item in domains_from_decision:
        domain = _extract_domain_string(item)
        if not domain:
            continue

        if domain not in state["memory"]["domain_history"]:
            state["memory"]["domain_history"][domain] = {"actions": []}

        action_type = "auto_blocked" if domain in auto_blocked else "recommended_block"
        state["memory"]["domain_history"][domain]["actions"].append({"action": action_type, "timestamp": timestamp, "reason": decision.get("reason", "N/A")})

    domains_to_watch = decision.get("domains_to_watch", [])
    for item in domains_to_watch:
        domain = _extract_domain_string(item)
        if not domain:
            continue

        if domain not in state["memory"]["domain_history"]:
            state["memory"]["domain_history"][domain] = {"actions": []}
        state["memory"]["domain_history"][domain]["actions"].append({"action": "watch", "timestamp": timestamp})

    state["memory"]["stats"]["total_decisions"] += 1
    if auto_blocked:
        state["memory"]["stats"]["auto_actions"] += len(auto_blocked)

    from settings import settings

    if len(state["memory"]["history"]) > settings.history_limit:
        state["memory"]["history"] = state["memory"]["history"][-settings.history_limit :]

    return state


def record_revert(domain: str, reason: str) -> None:
    """Record a domain revert in agent state"""
    state = load_agent_state()
    timestamp = datetime.now().isoformat()

    if "domain_history" not in state["memory"]:
        state["memory"]["domain_history"] = {}

    if domain not in state["memory"]["domain_history"]:
        state["memory"]["domain_history"][domain] = {"actions": []}

    state["memory"]["domain_history"][domain]["actions"].append({"action": "reverted", "timestamp": timestamp, "reason": reason})

    state["memory"]["stats"]["reverts"] += 1

    if "reflections" not in state["memory"]:
        state["memory"]["reflections"] = []

    reflection = {"timestamp": timestamp, "domain": domain, "lesson": f"Blocking {domain} was a mistake: {reason}"}
    state["memory"]["reflections"].append(reflection)

    if len(state["memory"]["reflections"]) > 10:
        state["memory"]["reflections"] = state["memory"]["reflections"][-10:]

    save_agent_state(state)
    logger.success(f"Domain {domain} revert recorded and lesson learned")
    logger.info(f"Total reverts: {state['memory']['stats']['reverts']}")
