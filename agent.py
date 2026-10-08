import sys
import time
import argparse
import concurrent.futures
from typing import Tuple

import requests
from colorama import init as colorama_init
from loguru import logger

from adguard_api import fetch_adguard_logs, get_custom_rules, unblock_domain_in_adguard
from agent_state import load_agent_state, record_revert, reverted_domains, save_agent_state, skipped_domains, update_agent_state_with_decision
from cli_interface import display_recommendations, execute_blocks, get_user_action, review_unblocks
from llm_analyzer import analyze_with_llm
from logging_config import init_logging
from network_analyzer import clean_decision, summarize
from router import get_router_devices
from settings import settings

colorama_init(autoreset=True)
init_logging(settings.log_level)


def fetch_adguard_data_parallel() -> Tuple[dict, set[str], set[str], dict]:
    """Fetch the AdGuard query log, AdGuard custom rules and router device names in parallel"""
    start_time = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        future_logs = executor.submit(fetch_adguard_logs)
        future_rules = executor.submit(get_custom_rules)
        future_devices = executor.submit(get_router_devices)
        log = future_logs.result()
        custom_blocked, custom_allowed = future_rules.result()
        devices = future_devices.result()
    logger.info(f"Parallel fetch completed in {time.time() - start_time:.2f}s")
    return log, custom_blocked, custom_allowed, devices


def revert_domain(domain: str, reason: str) -> None:
    """Revert a domain block and record the mistake for learning"""
    logger.info(f"Reverting block for domain: {domain}")
    logger.info(f"Reason: {reason}")

    if not unblock_domain_in_adguard(domain):
        logger.error("Failed to unblock domain")
        sys.exit(1)

    record_revert(domain, reason)


def print_agent_stats(state: dict) -> None:
    """Print agent statistics and configuration"""
    logger.info(f"Agent: {state['agent_meta']['name']} v{state['agent_meta']['version']}")
    logger.info(f"Goal: {state['goal']['primary']}")
    logger.info(f"Total decisions made: {state['memory']['stats']['total_decisions']}")
    logger.info(f"Reverts: {state['memory']['stats']['reverts']}")


def print_summary_stats(summary: dict) -> None:
    """Print network activity summary statistics"""
    logger.info(f"Total queries: {summary['total_queries']}")
    logger.info(f"Unique domains: {summary['unique_domains']}")
    logger.info(
        f"Domains under review: {len(summary['domain_counts'])} ({len(summary['skipped_domains'])} skipped before, {len(summary['suspicious_domains'])} suspicious)"
    )
    logger.info(f"Already blocked by AdGuard: {summary['blocked_count']}")


def handle_interactive_mode(indexed_domains: dict) -> tuple[list[str], bool]:
    """Let the user pick domains to block; returns (blocked, quit)"""
    action, selected = get_user_action(indexed_domains)
    if action != "block" or not selected:
        logger.info("No domains blocked, recording recommendations as skipped")
        return [], action == "quit"
    blocked = execute_blocks(selected)
    for domain in blocked:
        logger.success(f"  - {domain}")
    return blocked, False


def parse_args() -> argparse.Namespace:
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Home Network Agent - Monitor and block suspicious domains",
        epilog="""
                examples:
                python agent.py                                    Analyze and review recommendations
                python agent.py revert example.com "broke service" Unblock domain and record reason
                python agent.py revert 'abc*.example.com' "reason"  Quote wildcard rules so the shell leaves the * alone
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
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
        print_agent_stats(state)

        logger.info("Fetching data from AdGuard...")
        log, custom_blocked, custom_allowed, devices = fetch_adguard_data_parallel()

        logger.info("Analyzing network activity...")
        summary = summarize(log, custom_blocked, custom_allowed, skipped_domains(state))

        if "error" in summary:
            logger.error(summary["error"])
            sys.exit(1)

        summary["devices"] = devices
        print_summary_stats(summary)

        logger.info("Agent reasoning...")
        decision = analyze_with_llm(summary, state, custom_blocked, custom_allowed)
        decision = clean_decision(
            decision, custom_blocked, custom_allowed, set(summary["domain_counts"]), set(log["clients"]), reverted_domains(state), summary["possibly_broken"]
        )

        domain_clients = summary["domain_clients"]
        indexed_domains = display_recommendations(decision, domain_clients)

        blocked, quit_run = handle_interactive_mode(indexed_domains)

        if blocked:
            logger.warning('If something breaks, revert with: python agent.py revert <domain> "reason"')

        state = update_agent_state_with_decision(state, summary, decision, blocked)
        save_agent_state(state)
        logger.success("Agent state updated")

        # the query log proves these are blocked, so an allow rule is added even when no plain ||x^ custom rule covers them
        for item in [] if quit_run else review_unblocks(decision, summary["possibly_broken"]):
            if unblock_domain_in_adguard(item["domain"], blocked_by_list=True):
                record_revert(item["domain"], f"Unblocked: {item.get('reason', 'likely broke something')}")

    except requests.RequestException as e:
        logger.error(f"Network error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        logger.info("\nInterrupted by user")
        sys.exit(0)
    except Exception:
        logger.exception("Unexpected error")
        sys.exit(1)


if __name__ == "__main__":
    main()
