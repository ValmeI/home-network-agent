from colorama import Fore, Style
from loguru import logger

from adguard_api import block_domain_in_adguard


def _format_clients(clients: dict) -> str:
    if not clients:
        return ""
    total = sum(clients.values())
    parts = [f"{name}: {count}q" for name, count in clients.items()]
    return f" ({', '.join(parts)}; total: {total}q)"


def display_recommendations(decision: dict, domain_clients: dict) -> dict:
    """Display recommendations and return indexed domains"""
    domains_to_block = decision.get("domains_to_block", [])
    domains_to_watch = decision.get("domains_to_watch", [])
    domains_to_allow = decision.get("domains_to_allow", [])
    explanation = decision.get("explanation", {})
    
    if isinstance(explanation, str):
        explanation = {}
    
    indexed_domains = {}
    index = 1
    
    print(f"\n{'='*100}")
    print(f"{Style.BRIGHT}AGENT RECOMMENDATIONS{Style.RESET_ALL}")
    print(f"{'='*100}\n")
    
    if domains_to_block:
        print(f"{Style.BRIGHT}{Fore.RED}RECOMMENDED TO BLOCK:{Style.RESET_ALL}")
        for item in domains_to_block:
            if isinstance(item, dict):
                domain = item.get("domain")
                confidence = item.get("confidence", 0.0)
            else:
                domain = item
                confidence = 0.0
            
            confidence_color = Fore.GREEN if confidence >= 0.7 else Fore.YELLOW if confidence >= 0.5 else Fore.RED
            confidence_badge = f"{confidence_color}[{confidence:.2f}]{Style.RESET_ALL}"
            
            reason = explanation.get(domain, "No reason provided")
            clients_info = _format_clients(domain_clients.get(domain, {}))
            print(f"  [{index}] {Fore.RED}{domain}{Style.RESET_ALL} {confidence_badge} {Style.DIM}{clients_info}{Style.RESET_ALL}")
            print(f"      {Style.DIM}{reason}{Style.RESET_ALL}")
            indexed_domains[index] = {"domain": domain, "action": "block", "confidence": confidence}
            index += 1
        print()
    
    if domains_to_watch:
        print(f"{Style.BRIGHT}{Fore.YELLOW}RECOMMENDED TO WATCH:{Style.RESET_ALL}")
        for item in domains_to_watch:
            if isinstance(item, dict):
                domain = item.get("domain")
                confidence = item.get("confidence", 0.0)
            else:
                domain = item
                confidence = 0.0
            
            confidence_color = Fore.YELLOW if confidence >= 0.5 else Fore.RED
            confidence_badge = f"{confidence_color}[{confidence:.2f}]{Style.RESET_ALL}"
            
            reason = explanation.get(domain, "No reason provided")
            clients_info = _format_clients(domain_clients.get(domain, {}))
            print(f"  [{index}] {Fore.YELLOW}{domain}{Style.RESET_ALL} {confidence_badge} {Style.DIM}{clients_info}{Style.RESET_ALL}")
            print(f"      {Style.DIM}{reason}{Style.RESET_ALL}")
            indexed_domains[index] = {"domain": domain, "action": "watch", "confidence": confidence}
            index += 1
        print()
    
    if domains_to_allow:
        print(f"{Style.BRIGHT}{Fore.GREEN}SAFE TO ALLOW:{Style.RESET_ALL}")
        for domain in domains_to_allow:
            reason = explanation.get(domain, "No reason provided")
            clients_info = _format_clients(domain_clients.get(domain, {}))
            print(f"  {Fore.GREEN}{domain}{Style.RESET_ALL} {Style.DIM}{clients_info}{Style.RESET_ALL}")
            print(f"    {Style.DIM}{reason}{Style.RESET_ALL}")
        print()
    
    status = decision.get("decision", "N/A")
    reason = decision.get("reason", "N/A")
    confidence = decision.get("confidence", 0.0)
    status_colors = {"ALLOW": Fore.GREEN, "WATCH": Fore.YELLOW, "ALERT": Fore.RED}
    color = status_colors.get(status, Fore.WHITE)
    
    confidence_color = Fore.GREEN if confidence >= 0.7 else Fore.YELLOW if confidence >= 0.5 else Fore.RED
    
    print(f"{'='*100}")
    print(f"{Style.BRIGHT}Overall Status: {color}{status}{Style.RESET_ALL}")
    print(f"{color}Reason: {reason}{Style.RESET_ALL}")
    print(f"Confidence: {confidence_color}{confidence:.2f}{Style.RESET_ALL} (auto-block threshold: 0.7)")
    print(f"{'='*100}\n")
    
    return indexed_domains


def get_user_action(indexed_domains: dict) -> tuple[str, list[int]]:
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
            print("\nEnter numbers to block (comma-separated, or 'all'):")
            numbers_input = input("Numbers: ").strip().lower()
            
            if numbers_input == "all":
                return "block", list(indexed_domains.keys())
            
            try:
                numbers = [int(n.strip()) for n in numbers_input.split(",") if n.strip()]
                valid_numbers = [n for n in numbers if n in indexed_domains]
                
                if not valid_numbers:
                    print(f"{Fore.RED}No valid numbers entered{Style.RESET_ALL}")
                    continue
                
                return "block", valid_numbers
            except ValueError:
                print(f"{Fore.RED}Invalid input. Use numbers separated by commas.{Style.RESET_ALL}")
                continue
        
        print(f"{Fore.RED}Invalid choice. Use b/w/s/q{Style.RESET_ALL}")


def execute_blocks(indexed_domains: dict, selected_numbers: list[int], reason: str = "") -> list[str]:
    """Execute blocking for selected domains"""
    blocked = []
    
    for num in selected_numbers:
        domain_info = indexed_domains.get(num)
        if not domain_info:
            continue
        
        domain = domain_info["domain"]
        logger.info(f"Blocking {domain}...")
        
        if block_domain_in_adguard(domain, reason):
            blocked.append(domain)
    
    return blocked
