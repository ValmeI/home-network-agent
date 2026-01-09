import sys
import os
import time
import concurrent.futures
from typing import Tuple

import requests
from colorama import init as colorama_init
from loguru import logger

from adguard_api import fetch_adguard_logs, get_custom_blocked_domains, unblock_domain_in_adguard
from agent_state import load_agent_state, record_revert, save_agent_state, update_agent_state_with_decision
from cli_interface import display_recommendations, execute_blocks, get_user_action
from llm_analyzer import analyze_with_llm
from logging_config import init_logging
from network_analyzer import filter_history, summarize
from settings import settings

colorama_init(autoreset=True)
init_logging(settings.log_level)


def fetch_adguard_data_parallel() -> Tuple[dict, set[str]]:
    """Fetch AdGuard logs and blocked domains in parallel"""
    start_time = time.time()
    workers = settings.max_workers or os.cpu_count() or 4
    logger.info(f"Starting parallel fetch with {workers} workers...")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        logger.debug("Submitting fetch_adguard_logs task...")
        future_logs = executor.submit(fetch_adguard_logs)
        
        logger.debug("Submitting get_custom_blocked_domains task...")
        future_blocked = executor.submit(get_custom_blocked_domains)
        
        logger.debug("Waiting for results...")
        log = future_logs.result()
        custom_blocked = future_blocked.result()
    
    elapsed = time.time() - start_time
    logger.info(f"Parallel fetch completed in {elapsed:.2f}s")
    
    return log, custom_blocked


def revert_domain(domain: str, reason: str) -> None:
    """Revert a domain block and record the mistake for learning"""
    logger.info(f"Reverting block for domain: {domain}")
    logger.info(f"Reason: {reason}")
    
    if not unblock_domain_in_adguard(domain):
        logger.error("Failed to unblock domain")
        sys.exit(1)
    
    record_revert(domain, reason)


def main() -> None:
    if len(sys.argv) > 1 and sys.argv[1] == "revert":
        if len(sys.argv) < 4:
            logger.error("Usage: python agent.py revert <domain> <reason>")
            sys.exit(1)
        domain = sys.argv[2]
        reason = " ".join(sys.argv[3:])
        revert_domain(domain, reason)
        return

    try:
        logger.info("Loading agent state...")
        state = load_agent_state()
        logger.info(f"Agent: {state['agent_meta']['name']} v{state['agent_meta']['version']}")
        logger.info(f"Goal: {state['goal']['primary']}")
        logger.info(f"Total decisions made: {state['memory']['stats']['total_decisions']}")
        logger.info(f"Auto actions: {state['memory']['stats']['auto_actions']} | Reverts: {state['memory']['stats']['reverts']}")

        logger.info("Fetching data from AdGuard...")
        log, custom_blocked = fetch_adguard_data_parallel()

        logger.info("Analyzing network activity...")
        summary = summarize(log, custom_blocked)

        if "error" in summary:
            logger.error(summary["error"])
            sys.exit(1)

        logger.info(f"Total queries: {summary['total_queries']}")
        logger.info(f"Unique domains: {summary['unique_domains']}")
        logger.info(f"New domains: {len(summary['new_domains'])}")
        logger.info(f"Already blocked by AdGuard: {summary['blocked_count']}")

        history = state["memory"]["history"][-settings.history_limit :]
        filtered_history = filter_history(history, custom_blocked)

        logger.info("Agent reasoning...")
        decision = analyze_with_llm(summary, filtered_history, custom_blocked, state["goal"])

        domain_clients = decision.get("summary", {}).get("domain_clients", {})
        indexed_domains = display_recommendations(decision, domain_clients)

        action, selected_numbers = get_user_action(indexed_domains)
        
        if action == "quit":
            logger.info("Exiting without changes")
            sys.exit(0)
        
        if action == "skip":
            logger.info("Skipping actions")
            state["memory"]["stats"]["total_decisions"] += 1
            state["memory"]["stats"]["manual_confirmations"] += 1
            save_agent_state(state)
            sys.exit(0)
        
        auto_blocked = []
        if action == "block" and selected_numbers:
            logger.info(f"Blocking {len(selected_numbers)} domains...")
            block_reason = decision.get("reason", "Agent recommendation")[:60]
            auto_blocked = execute_blocks(indexed_domains, selected_numbers, block_reason)
            
            if auto_blocked:
                logger.success(f"Successfully blocked {len(auto_blocked)} domains")
                for domain in auto_blocked:
                    logger.success(f"  - {domain}")
                logger.warning(f"If something breaks, revert with: python agent.py revert <domain> \"reason\"")

        state = update_agent_state_with_decision(state, summary, decision, auto_blocked)
        save_agent_state(state)
        logger.success("Agent state updated")

    except requests.RequestException as e:
        logger.error(f"Network error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        logger.info("\nInterrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.exception("Unexpected error")
        sys.exit(1)


if __name__ == "__main__":
    main()
