"""PortWatcher - Main Application Entry Point."""

import sys
import os
import socket
import argparse

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "Protocols"))

from Tcp import scan_tcp_ports
from Udp import scan_udp_ports
from AllProtocol import scan_all_ports
from utils import (
    Color, prompt_export, export_to_csv, export_to_json,
)

VERSION = "1.1.0"


def validate_target(target):
    """Validate and resolve a target. Returns resolved IP or None."""
    if not target or not target.strip():
        return None
    try:
        info = socket.getaddrinfo(target.strip(), None, socket.AF_INET)
        return info[0][4][0]
    except (socket.gaierror, IndexError):
        return None


def parse_port_spec(spec):
    """Parse '22,80,443' or '1-1000' into a sorted list of unique ports."""
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_s, _, end_s = part.partition("-")
            try:
                start, end = int(start_s), int(end_s)
            except ValueError:
                raise ValueError(f"invalid port range '{part}'")
            if start > end:
                raise ValueError(f"invalid port range '{part}'")
            ports.update(range(start, end + 1))
        else:
            try:
                ports.add(int(part))
            except ValueError:
                raise ValueError(f"invalid port '{part}'")
    if not ports:
        raise ValueError("no ports specified")
    for port in ports:
        if not 1 <= port <= 65535:
            raise ValueError(f"port out of range: {port}")
    return sorted(ports)


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


def interactive_menu():
    """Main interactive menu loop."""
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
                results = scan_all_ports(target)
            elif choice == "2":
                results = scan_tcp_ports(target)
            else:
                results = scan_udp_ports(target)
            prompt_export(results)
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


def export_results(results, filepath):
    """Export results based on the output file extension. Returns bool."""
    ext = os.path.splitext(filepath)[1].lower()
    if ext == ".csv":
        return export_to_csv(results, filepath)
    if ext == ".json":
        return export_to_json(results, filepath)
    print(f"  {Color.RED}Unknown output format '{ext}'. Use .csv or .json.{Color.RESET}")
    return False


def build_parser():
    """Build the command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="PortWatcher",
        description="Advanced network port scanner (TCP/UDP).",
    )
    parser.add_argument(
        "target", nargs="?",
        help="Target hostname or IP. Omit to use the interactive menu.",
    )
    parser.add_argument(
        "-p", "--protocol", choices=["tcp", "udp", "all"], default="tcp",
        help="Scanning protocol (default: tcp).",
    )
    parser.add_argument(
        "-r", "--range", dest="port_range",
        help="Ports to scan, e.g. '22,80,443' or '1-1000'. Defaults to common "
             "ports. For --protocol all it applies to the TCP range.",
    )
    parser.add_argument(
        "-o", "--output",
        help="Export results to a .csv or .json file.",
    )
    parser.add_argument(
        "--timeout", type=float, default=0.5,
        help="Per-port socket timeout in seconds (default: 0.5).",
    )
    parser.add_argument(
        "--workers", type=int, default=100,
        help="Maximum concurrent scanning threads (default: 100).",
    )
    parser.add_argument(
        "-v", "--version", action="version",
        version=f"PortWatcher {VERSION}",
    )
    return parser


def run_cli(args):
    """Execute a non-interactive scan from parsed CLI arguments."""
    ports = None
    if args.port_range:
        try:
            ports = parse_port_spec(args.port_range)
        except ValueError as e:
            print(f"  {Color.RED}Error: {e}{Color.RESET}")
            return 1

    if args.protocol == "tcp":
        results = scan_tcp_ports(
            args.target, ports=ports, timeout=args.timeout, workers=args.workers
        )
    elif args.protocol == "udp":
        results = scan_udp_ports(
            args.target, ports=ports, timeout=args.timeout, workers=args.workers
        )
    else:
        results = scan_all_ports(
            args.target, tcp_ports=ports, timeout=args.timeout, workers=args.workers
        )

    if args.output:
        if not results:
            print(f"  {Color.YELLOW}No results to export.{Color.RESET}")
            return 1
        if export_results(results, args.output):
            print(f"  {Color.GREEN}Results exported to {args.output}{Color.RESET}")
            return 0
        return 1
    return 0


def main(argv=None):
    """Entry point: run CLI when a target is given, else the menu."""
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.target:
        return run_cli(args)
    interactive_menu()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(f"\n\n  {Color.GREEN}Goodbye!{Color.RESET}\n")
        sys.exit(0)
