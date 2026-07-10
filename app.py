"""PortWatcher - Main Application Entry Point."""

import sys
import os
import socket

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "Protocols"))

from Tcp import scan_tcp_ports
from Udp import scan_udp_ports
from AllProtocol import scan_all_ports


class Color:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"


def validate_target(target):
    """Validate and resolve a target. Returns resolved IP or None."""
    if not target or not target.strip():
        return None
    try:
        info = socket.getaddrinfo(target.strip(), None, socket.AF_INET)
        return info[0][4][0]
    except (socket.gaierror, IndexError):
        return None


def get_target():
    """Prompt for target with validation."""
    c = Color
    while True:
        target = input(f"  {c.CYAN}>{c.RESET} Enter target IP or hostname: ").strip()
        if not target:
            print(f"  {c.RED}Please enter a valid target.{c.RESET}")
            continue
        resolved = validate_target(target)
        if resolved:
            return resolved
        print(f"  {c.RED}Could not resolve '{target}'. Please try again.{c.RESET}")


def show_banner():
    """Show application banner."""
    c = Color
    print()
    print(f"{c.CYAN}{'=' * 50}{c.RESET}")
    print(f"{c.BOLD}{c.CYAN}  PortWatcher - Network Port Scanner{c.RESET}")
    print(f"{c.CYAN}{'=' * 50}{c.RESET}")


def show_menu():
    """Show main menu."""
    c = Color
    print()
    print(f"  {c.WHITE}1{c.RESET}. All Protocols  {c.DIM}(TCP 1-65535 + common UDP){c.RESET}")
    print(f"  {c.WHITE}2{c.RESET}. TCP            {c.DIM}(common TCP ports){c.RESET}")
    print(f"  {c.WHITE}3{c.RESET}. UDP            {c.DIM}(common UDP ports){c.RESET}")
    print(f"  {c.WHITE}4{c.RESET}. Exit")
    print()


def main():
    """Main application loop."""
    c = Color

    while True:
        show_banner()
        show_menu()

        choice = input(f"  {c.CYAN}>{c.RESET} Select option (1-4): ").strip()

        if choice == "4":
            print(f"\n  {c.GREEN}Goodbye!{c.RESET}\n")
            break
        elif choice in ("1", "2", "3"):
            target = get_target()
            print()
            if choice == "1":
                scan_all_ports(target)
            elif choice == "2":
                scan_tcp_ports(target)
            else:
                scan_udp_ports(target)
        else:
            print(f"\n  {c.RED}Invalid option. Please select 1-4.{c.RESET}\n")
            continue

        print()
        again = input(f"  {c.CYAN}>{c.RESET} Return to menu? (y/n): ").strip().lower()
        if again != "y":
            print(f"\n  {c.GREEN}Goodbye!{c.RESET}\n")
            break

        if os.name == "nt":
            os.system("cls")
        else:
            os.system("clear")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n  {Color.GREEN}Goodbye!{Color.RESET}\n")
        sys.exit(0)
