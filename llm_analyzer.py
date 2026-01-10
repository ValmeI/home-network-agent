import json
from datetime import datetime

from loguru import logger
from openai import OpenAI

from agent_state import load_agent_state
from settings import settings

client = OpenAI(api_key=settings.openai_api_key)


def analyze_with_llm(summary: dict, history: list[dict], custom_blocked: set[str], goal: dict) -> dict:
    """Analyze network activity with LLM and get decision"""
    try:
        with open(settings.prompt_file) as f:
            prompt_template = f.read()
    except FileNotFoundError:
        logger.error(f"Prompt file not found: {settings.prompt_file}")
        raise

    state = load_agent_state()
    stats = state.get("memory", {}).get("stats", {})
    domain_history = state.get("memory", {}).get("domain_history", {})
    reflections = state.get("memory", {}).get("reflections", [])[-3:]

    learning_context = {"stats": stats, "domain_history": {k: v for k, v in list(domain_history.items())[-20:]}, "reflections": reflections}

    user_message = (
        f"AGENT GOAL:\n{json.dumps(goal, indent=2)}\n\n"
        f"YOUR LEARNING (past behavior & mistakes):\n{json.dumps(learning_context, indent=2)}\n\n"
        f"CURRENT STATS:\n{json.dumps(summary, indent=2)}\n\n"
        f"PREVIOUS DECISIONS:\n{json.dumps(history, indent=2)}\n\n"
        f"TRUSTED DOMAINS (should be ALLOW unless clearly malicious):\n{json.dumps(settings.trusted_domains, indent=2)}\n\n"
        f"ALREADY BLOCKED IN ADGUARD (do NOT include in WATCH or BLOCK lists):\n{json.dumps(sorted(custom_blocked), indent=2)}\n\n"
        "Analyze the current network activity and decide on the overall threat level or notable patterns.\n"
        "LEARN from your domain_history: if you've seen patterns of false positives or service breaks, adjust your confidence accordingly."
    )

    prompt_size = len(prompt_template) + len(user_message)
    logger.info(f"LLM prompt size: {prompt_size} characters ({prompt_size / 1024:.2f} KB)")

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
