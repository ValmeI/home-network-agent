from colorama import Fore, Style
from loguru import logger

from adguard_api import block_domains_in_adguard
from network_analyzer import is_trusted_domain
from settings import settings


def _confidence_color(confidence: float) -> str:
    return Fore.GREEN if confidence >= settings.confidence_high else Fore.YELLOW if confidence >= settings.confidence_medium else Fore.RED


def _format_clients(clients: dict) -> str:
    if not clients:
        return ""
    total = sum(clients.values())
    parts = [f"{name}: {count}q" for name, count in clients.items()]
    return f" ({', '.join(parts)}; total: {total}q)"


def display_recommendations(decision: dict, domain_clients: dict) -> dict:
    """Display recommendations and return indexed domains"""
    domains_to_block = decision["domains_to_block"]
    domains_to_watch = decision["domains_to_watch"]
    domains_to_allow = [d for d in decision.get("domains_to_allow", []) if isinstance(d, str) and not is_trusted_domain(d.lower())]
    explanation = decision.get("explanation", {})

    if isinstance(explanation, str):
        explanation = {}

    indexed_domains = {}
    index = 1
    logger.info("Displaying agent recommendations...")
    print(f"\n{'=' * 100}")
    print(f"{Style.BRIGHT}AGENT RECOMMENDATIONS{Style.RESET_ALL}")
    print(f"{'=' * 100}\n")

    if domains_to_allow:
        print(f"{Style.BRIGHT}{Fore.GREEN}SAFE TO ALLOW:{Style.RESET_ALL}")
        for domain in domains_to_allow:
            reason = explanation.get(domain, "No reason provided")
            clients_info = _format_clients(domain_clients.get(domain, {}))
            print(f"  {Fore.GREEN}{domain}{Style.RESET_ALL} {Style.DIM}{clients_info}{Style.RESET_ALL}")
            print(f"    {Style.DIM}{reason}{Style.RESET_ALL}")
        print()

    parents = {}
    subdomain_only = []
    for item in domains_to_block:
        if item.get("parent_domain"):
            parents.setdefault(item["parent_domain"], []).append(item)
        else:
            subdomain_only.append(item)

    if parents:
        print(f"{Style.BRIGHT}{Fore.RED}BLOCK WHOLE DOMAIN:{Style.RESET_ALL}")
        for parent, items in parents.items():
            subdomains = [
                {"domain": i["domain"], "action": "block", "confidence": i.get("confidence", 0.0), "reason": explanation.get(i["domain"], "No reason provided")}
                for i in items
            ]
            confidence = max(sub["confidence"] for sub in subdomains)
            confidence_color = _confidence_color(confidence)
            reason = items[0].get("parent_reason") or subdomains[0]["reason"]
            print(f"  [{index}] {Fore.RED}{parent}{Style.RESET_ALL}  - confidence score: {confidence_color}[{confidence:.2f}]{Style.RESET_ALL}")
            print(f"      {Style.DIM}{reason}{Style.RESET_ALL}")
            print(f"      {Style.DIM}covers: {', '.join(sub['domain'] for sub in subdomains)} (enter {index}s to block only these){Style.RESET_ALL}")
            indexed_domains[index] = {"domain": parent, "action": "parent", "confidence": confidence, "reason": reason, "subdomains": subdomains}
            index += 1
        print()

    if subdomain_only:
        print(f"{Style.BRIGHT}{Fore.RED}BLOCK SUBDOMAIN ONLY:{Style.RESET_ALL}")
        for item in subdomain_only:
            domain = item["domain"]
            confidence = item.get("confidence", 0.0)
            confidence_color = _confidence_color(confidence)
            confidence_badge = f" - confidence score: {confidence_color}[{confidence:.2f}]{Style.RESET_ALL}"

            reason = explanation.get(domain, "No reason provided")
            clients_info = _format_clients(domain_clients.get(domain, {}))
            print(f"  [{index}] {Fore.RED}{domain}{Style.RESET_ALL} {confidence_badge} {Style.DIM}{clients_info}{Style.RESET_ALL}")
            print(f"      {Style.DIM}{reason}{Style.RESET_ALL}")
            indexed_domains[index] = {"domain": domain, "action": "block", "confidence": confidence, "reason": reason}
            index += 1
        print()

    if domains_to_watch:
        print(f"{Style.BRIGHT}{Fore.YELLOW}RECOMMENDED TO WATCH:{Style.RESET_ALL}")

        for item in sorted(domains_to_watch, key=lambda x: x.get("confidence", 0.0), reverse=True):
            domain = item["domain"]
            confidence = item.get("confidence", 0.0)
            confidence_color = Fore.YELLOW if confidence >= settings.confidence_medium else Fore.RED
            confidence_badge = f"{confidence_color}[{confidence:.2f}]{Style.RESET_ALL}"

            reason = explanation.get(domain, "No reason provided")
            clients_info = _format_clients(domain_clients.get(domain, {}))
            print(f"  [{index}] {Fore.YELLOW}{domain}{Style.RESET_ALL} {confidence_badge} {Style.DIM}{clients_info}{Style.RESET_ALL}")
            print(f"      {Style.DIM}{reason}{Style.RESET_ALL}")
            indexed_domains[index] = {"domain": domain, "action": "watch", "confidence": confidence, "reason": reason}
            index += 1
        print()

    status = decision.get("decision", "N/A")
    reason = decision.get("reason", "N/A")
    status_colors = {"ALLOW": Fore.GREEN, "WATCH": Fore.YELLOW, "ALERT": Fore.RED}
    color = status_colors.get(status, Fore.WHITE)

    print(f"{'=' * 100}")
    print(f"{Style.BRIGHT}Overall Status: {color}{status}{Style.RESET_ALL}")
    print(f"{color}Reason: {reason}{Style.RESET_ALL}")
    print(f"{'=' * 100}\n")

    return indexed_domains


def parse_selection(numbers_input: str, indexed_domains: dict) -> list[dict]:
    """'3' picks entry 3; '3s' on a whole-domain entry picks only its covered subdomains"""
    selected = []
    for token in numbers_input.replace(",", " ").split():
        subdomains_only = token.endswith("s")
        info = indexed_domains.get(int(token[:-1] if subdomains_only else token))
        if not info:
            continue
        if subdomains_only:
            selected.extend(info.get("subdomains", []))
        else:
            selected.append(info)
    return selected


def get_block_selection(indexed_domains: dict) -> list[dict]:
    """Get domains to block from user input"""
    while True:
        print("\nEnter what to block:")
        print("  1 3 5       = those numbers (comma or space separated)")
        has_parent = any(info["action"] == "parent" for info in indexed_domains.values())
        if has_parent:
            print("  1s          = whole-domain entry 1, but only its listed subdomains")
        print("  all         = everything as shown" + (" (whole domains + subdomains)" if has_parent else ""))
        if has_parent:
            print("  all parents = only the BLOCK WHOLE DOMAIN entries")
            print("  all subs    = everything, but never a whole domain (subdomains only)")
        numbers_input = " ".join(input("Choice: ").lower().split())

        keyword_selection = {
            "all": [info for info in indexed_domains.values() if info["action"] in ("block", "parent")],
            "all parents": [info for info in indexed_domains.values() if info["action"] == "parent"],
            "all subs": [
                sub
                for info in indexed_domains.values()
                for sub in (info.get("subdomains", []) if info["action"] == "parent" else [info] if info["action"] == "block" else [])
            ],
        }
        if numbers_input in keyword_selection:
            if keyword_selection[numbers_input]:
                return keyword_selection[numbers_input]
            print(f"{Fore.RED}Nothing to block for '{numbers_input}'{Style.RESET_ALL}")
            continue

        try:
            selected = parse_selection(numbers_input, indexed_domains)
            if not selected:
                print(f"{Fore.RED}No valid numbers entered{Style.RESET_ALL}")
                continue

            return selected
        except ValueError:
            print(f"{Fore.RED}Invalid input. Use numbers separated by commas or spaces.{Style.RESET_ALL}")
            continue


def get_user_action(indexed_domains: dict) -> tuple[str, list[dict]]:
    """Get user choice interactively"""
    if not indexed_domains:
        print("No actions to take. Press Enter to exit.")
        input()
        return "skip", []

    print("What do you want to do?")
    print(f"  {Fore.RED}[b]{Style.RESET_ALL} Block selected domains")
    print(f"  {Fore.YELLOW}[w]{Style.RESET_ALL} Keep watching")
    print(f"  {Fore.GREEN}[s]{Style.RESET_ALL} Skip / Do nothing")
    print(f"  {Fore.CYAN}[q]{Style.RESET_ALL} Quit")

    while True:
        choice = input("\nYour choice: ").strip().lower()

        if choice == "q":
            return "quit", []

        if choice == "s":
            return "skip", []

        if choice == "w":
            return "watch", []

        if choice == "b":
            return "block", get_block_selection(indexed_domains)

        print(f"{Fore.RED}Invalid choice. Use b/w/s/q{Style.RESET_ALL}")


def review_unblocks(decision: dict, possibly_broken: list[dict]) -> list[dict]:
    """Show the AI's unblock suggestions (blocked domains a device keeps retrying) and return the ones the user picks"""
    suggestions = decision.get("domains_to_unblock", [])
    if not suggestions:
        return []
    by_domain = {b["domain"]: b for b in possibly_broken}
    print(f"\n{'=' * 100}")
    print(f"{Style.BRIGHT}{Fore.GREEN}POSSIBLY BROKEN BY A BLOCK - UNBLOCK?{Style.RESET_ALL}")
    for i, item in enumerate(suggestions, 1):
        info = by_domain[item["domain"]]
        clients = _format_clients(info["clients"])
        print(f"  [{i}] {Fore.GREEN}{item['domain']}{Style.RESET_ALL}  - confidence score: [{item.get('confidence', 0):.2f}]  {clients}")
        print(f"      {Style.DIM}{item.get('reason', '')}{Style.RESET_ALL}")
        print(f"      {Style.DIM}blocked {info['blocked']}x by {info['rule'][0]}{Style.RESET_ALL}")
    print(f"{'=' * 100}")
    while True:
        raw = input("Numbers to unblock (Enter = none): ").replace(",", " ").split()
        try:
            return [suggestions[n - 1] for n in dict.fromkeys(int(x) for x in raw) if 1 <= n <= len(suggestions)]
        except ValueError:
            print(f"{Fore.RED}Use numbers separated by spaces or commas{Style.RESET_ALL}")


def execute_blocks(selected: list[dict]) -> list[str]:
    """Block the selected domains in one AdGuard write, parents first so covered subdomains are skipped"""
    ordered = sorted(selected, key=lambda info: info["action"] != "parent")
    return block_domains_in_adguard([(info["domain"], info["reason"]) for info in ordered])
