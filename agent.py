import sys
import os
import time
import argparse
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


def print_agent_stats(state: dict, is_auto_mode: bool) -> None:
    """Print agent statistics and configuration"""
    logger.info(f"Agent: {state['agent_meta']['name']} v{state['agent_meta']['version']}")
    logger.info(f"Goal: {state['goal']['primary']}")
    logger.info(f"Total decisions made: {state['memory']['stats']['total_decisions']}")
    logger.info(f"Auto actions: {state['memory']['stats']['auto_actions']} | Reverts: {state['memory']['stats']['reverts']}")
    
    if is_auto_mode:
        logger.info(f"AUTO MODE: Will block domains with confidence >= {settings.auto_block_threshold}")


def print_summary_stats(summary: dict) -> None:
    """Print network activity summary statistics"""
    logger.info(f"Total queries: {summary['total_queries']}")
    logger.info(f"Unique domains: {summary['unique_domains']}")
    logger.info(f"New domains: {len(summary['new_domains'])}")
    logger.info(f"Already blocked by AdGuard: {summary['blocked_count']}")


def handle_auto_mode(indexed_domains: dict, state: dict) -> list[str]:
    """Handle automatic blocking mode for high-confidence domains"""
    if settings.auto_block_threshold <= 0:
        return []
    
    high_confidence_domains = [
        idx for idx, domain_info in indexed_domains.items()
        if domain_info["confidence"] >= settings.auto_block_threshold
    ]
    
    if not high_confidence_domains:
        logger.info("AUTO MODE: No domains meet auto-block threshold")
        return []
    
    logger.warning(f"AUTO MODE: Blocking {len(high_confidence_domains)} high-confidence domains")
    block_reason = f"Auto-blocked (confidence >= {settings.auto_block_threshold})"
    auto_blocked = execute_blocks(indexed_domains, high_confidence_domains, block_reason)
    
    if auto_blocked:
        logger.success(f"Successfully auto-blocked {len(auto_blocked)} domains")
        for domain in auto_blocked:
            logger.success(f"  - {domain}")
        state["memory"]["stats"]["auto_actions"] += len(auto_blocked)
    
    return auto_blocked


def handle_interactive_mode(indexed_domains: dict, decision: dict) -> list[str]:
    """Handle interactive mode where user selects domains to block"""
    action, selected_numbers = get_user_action(indexed_domains)
    
    if action == "quit":
        logger.info("Exiting without changes")
        sys.exit(0)
    
    if action == "skip":
        logger.info("Skipping actions")
        return []
    
    if action == "block" and selected_numbers:
        logger.info(f"Blocking {len(selected_numbers)} domains...")
        block_reason = decision.get("reason", "Agent recommendation")[:60]
        auto_blocked = execute_blocks(indexed_domains, selected_numbers, block_reason)
        
        if auto_blocked:
            logger.success(f"Successfully blocked {len(auto_blocked)} domains")
            for domain in auto_blocked:
                logger.success(f"  - {domain}")
        
        return auto_blocked
    
    return []


def parse_args() -> argparse.Namespace:
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Home Network Agent - Monitor and block suspicious domains",
        epilog="""
                examples:
                python agent.py                                    Run in interactive mode
                python agent.py --auto                             Auto-block high-confidence domains
                python agent.py revert example.com "broke service" Unblock domain and record reason
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--auto", action="store_true", help=f"Automatically block domains with confidence >= {settings.auto_block_threshold}")
    parser.add_argument("command", nargs="?", help="Command: revert")
    parser.add_argument("domain", nargs="?", help="Domain to revert (used with revert command)")
    parser.add_argument("reason", nargs="*", help="Reason for reverting (used with revert command)")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    
    if args.command == "revert":
        if not args.domain or not args.reason:
            logger.error("Usage: python agent.py revert <domain> <reason>")
            sys.exit(1)
        domain = args.domain
        reason = " ".join(args.reason)
        revert_domain(domain, reason)
        return

    try:
        logger.info("Loading agent state...")
        state = load_agent_state()
        print_agent_stats(state, args.auto)

        logger.info("Fetching data from AdGuard...")
        log, custom_blocked = fetch_adguard_data_parallel()

        logger.info("Analyzing network activity...")
        summary = summarize(log, custom_blocked)

        if "error" in summary:
            logger.error(summary["error"])
            sys.exit(1)

        print_summary_stats(summary)

        history = state["memory"]["history"][-settings.history_limit :]
        filtered_history = filter_history(history, custom_blocked)

        logger.info("Agent reasoning...")
        decision = analyze_with_llm(summary, filtered_history, custom_blocked, state["goal"])

        domain_clients = decision.get("summary", {}).get("domain_clients", {})
        indexed_domains = display_recommendations(decision, domain_clients)

        if args.auto:
            auto_blocked = handle_auto_mode(indexed_domains, state)
        else:
            auto_blocked = handle_interactive_mode(indexed_domains, decision)
            
            if not auto_blocked:
                state["memory"]["stats"]["total_decisions"] += 1
                state["memory"]["stats"]["manual_confirmations"] += 1
                save_agent_state(state)
                sys.exit(0)

        if auto_blocked:
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
