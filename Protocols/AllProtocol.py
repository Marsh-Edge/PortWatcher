"""Combined TCP and UDP scanner - scans all TCP ports (1-65535) + common UDP ports."""

import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from utils import (
    Color, scan_tcp_port, scan_udp_port, COMMON_UDP_PORTS,
    resolve_target, get_local_ip, print_banner, print_port_table,
    run_threaded_scan,
)

TIMEOUT = 0.5
MAX_WORKERS = 100
ALL_TCP_PORTS = list(range(1, 65536))


def print_combined_results(tcp_open, udp_open, tcp_scanned, udp_scanned, duration):
    """Print combined TCP + UDP scan results."""
    c = Color
    tcp_rows = sorted(tcp_open, key=lambda x: x["port"])
    udp_rows = sorted(udp_open, key=lambda x: x["port"])

    print()
    print(f"{c.CYAN}{'=' * 60}{c.RESET}")
    print(f"{c.BOLD}  Results - All Protocols (TCP + UDP){c.RESET}")
    print(f"{c.CYAN}{'=' * 60}{c.RESET}")

    has_results = False

    if tcp_rows:
        has_results = True
        print(f"\n  {c.GREEN}{c.BOLD}TCP: {len(tcp_rows)} open port(s):{c.RESET}\n")
        print_port_table(tcp_rows)

    if udp_rows:
        has_results = True
        print(f"\n  {c.GREEN}{c.BOLD}UDP: {len(udp_rows)} open port(s):{c.RESET}\n")
        print_port_table(udp_rows)

    if not has_results:
        print(f"\n  {c.RED}No open ports found.{c.RESET}")

    total_scanned = tcp_scanned + udp_scanned
    total_open = len(tcp_rows) + len(udp_rows)
    print(f"\n{c.CYAN}{'-' * 60}{c.RESET}")
    print(
        f"  Scanned: {total_scanned:,} ports "
        f"({tcp_scanned:,} TCP + {udp_scanned:,} UDP) | "
        f"Open: {total_open} | Time: {duration}"
    )
    print(f"{c.CYAN}{'=' * 60}{c.RESET}\n")


def scan_all_ports(target, tcp_ports=None, udp_ports=None,
                   timeout=TIMEOUT, workers=MAX_WORKERS, show_progress=True):
    """Scan TCP ports and common UDP ports. Returns combined list."""
    resolved = resolve_target(target)
    if not resolved:
        print(f"\n  {Color.RED}Error: Could not resolve '{target}'{Color.RESET}\n")
        return []

    if tcp_ports is None:
        tcp_ports = ALL_TCP_PORTS
    if udp_ports is None:
        udp_ports = COMMON_UDP_PORTS

    local_ip = get_local_ip()
    total = len(tcp_ports) + len(udp_ports)

    print_banner(
        resolved, local_ip, "All Protocols (TCP + UDP)", total,
        f"({len(tcp_ports):,} TCP + {len(udp_ports):,} UDP)",
    )

    def dispatch(item):
        proto, port = item
        if proto == "TCP":
            return scan_tcp_port(resolved, port, timeout, proto="TCP")
        return scan_udp_port(resolved, port, timeout, proto="UDP")

    items = [("TCP", p) for p in tcp_ports] + [("UDP", p) for p in udp_ports]

    start = time.time()
    results, interrupted = run_threaded_scan(
        dispatch, items, max_workers=workers, show_progress=show_progress
    )
    if interrupted:
        print(f"\n\n  {Color.YELLOW}Scan interrupted by user.{Color.RESET}")

    tcp_open = sorted((r for r in results if r["proto"] == "TCP"),
                      key=lambda x: x["port"])
    udp_open = sorted((r for r in results if r["proto"] == "UDP"),
                      key=lambda x: x["port"])

    duration = f"{time.time() - start:.1f}s"
    print_combined_results(tcp_open, udp_open, len(tcp_ports), len(udp_ports), duration)
    return tcp_open + udp_open


if __name__ == "__main__":
    target = input("Enter hostname or IP to scan: ").strip()
    if not target:
        print("No target specified.")
        sys.exit(1)
    scan_all_ports(target)
