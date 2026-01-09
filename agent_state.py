import json
from datetime import datetime

from loguru import logger

AGENT_STATE_FILE = "agent_state.json"


def load_agent_state() -> dict:
    """Load agent state from file or initialize default state"""
    try:
        with open(AGENT_STATE_FILE) as f:
            return json.load(f)
    except FileNotFoundError:
        logger.info("No agent state found, initializing default state")
        default_state = {
            "agent_meta": {
                "name": "home-network-agent",
                "version": "0.1",
                "started_at": datetime.now().isoformat(),
            },
            "goal": {
                "primary": "Reduce unwanted tracking while minimizing service breakage",
                "constraints": [
                    "Avoid blocking essential services",
                    "Prefer reversible actions",
                    "Require confidence >= 0.7 for auto-action",
                ],
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
    with open(AGENT_STATE_FILE, "w") as f:
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
        seen.update(decision.get("domains_to_block", []))
        seen.update(decision.get("domains_to_watch", []))
        seen.update(decision.get("domains_to_allow", []))
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

    history_entry = {
        "timestamp": timestamp,
        "observations": state["last_decision"]["observations"],
        "decision": state["last_decision"]["decision"],
    }
    state["memory"]["history"].append(history_entry)

    if "domain_history" not in state["memory"]:
        state["memory"]["domain_history"] = {}

    for domain in decision.get("domains_to_block", []):
        if domain not in state["memory"]["domain_history"]:
            state["memory"]["domain_history"][domain] = {"actions": []}
        
        action_type = "auto_blocked" if domain in auto_blocked else "recommended_block"
        state["memory"]["domain_history"][domain]["actions"].append({
            "action": action_type,
            "timestamp": timestamp,
            "reason": decision.get("reason", "N/A"),
        })

    for domain in decision.get("domains_to_watch", []):
        if domain not in state["memory"]["domain_history"]:
            state["memory"]["domain_history"][domain] = {"actions": []}
        state["memory"]["domain_history"][domain]["actions"].append({
            "action": "watch",
            "timestamp": timestamp,
        })

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
    
    state["memory"]["domain_history"][domain]["actions"].append({
        "action": "reverted",
        "timestamp": timestamp,
        "reason": reason,
    })
    
    state["memory"]["stats"]["reverts"] += 1
    
    if "reflections" not in state["memory"]:
        state["memory"]["reflections"] = []
    
    reflection = {
        "timestamp": timestamp,
        "domain": domain,
        "lesson": f"Blocking {domain} was a mistake: {reason}",
    }
    state["memory"]["reflections"].append(reflection)
    
    if len(state["memory"]["reflections"]) > 10:
        state["memory"]["reflections"] = state["memory"]["reflections"][-10:]
    
    save_agent_state(state)
    logger.success(f"Domain {domain} revert recorded and lesson learned")
    logger.info(f"Total reverts: {state['memory']['stats']['reverts']}")
