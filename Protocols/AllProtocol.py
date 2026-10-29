"""Combined TCP and UDP scanner - scans all TCP ports (1-65535) + common UDP ports."""

import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from utils import (
    Color, scan_tcp_port, scan_udp_port, COMMON_UDP_PORTS, DEFAULT_TIMEOUT,
    DEFAULT_WORKERS, DEFAULT_RETRIES, DEFAULT_BANNER_TIMEOUT, resolve_target,
    get_local_ip, print_banner, print_port_table, run_threaded_scan,
    reverse_dns, attach_local_processes,
)

TIMEOUT = DEFAULT_TIMEOUT
MAX_WORKERS = DEFAULT_WORKERS
ALL_TCP_PORTS = list(range(1, 65536))


def print_combined_results(tcp_open, udp_open, tcp_scanned, udp_scanned, duration):
    """Print combined TCP + UDP scan results."""
    c = Color
    tcp_rows = sorted(tcp_open, key=lambda entry: entry["port"])
    udp_rows = sorted(udp_open, key=lambda entry: entry["port"])

    print()
    print(f"{c.CYAN}{'=' * 60}{c.RESET}")
    print(f"{c.BOLD}  Results - All Protocols (TCP + UDP){c.RESET}")
    print(f"{c.CYAN}{'=' * 60}{c.RESET}")

    has_results = False

    if tcp_rows:
        has_results = True
        print(f"\n  {c.GREEN}{c.BOLD}TCP: {len(tcp_rows)} port(s):{c.RESET}\n")
        print_port_table(tcp_rows)

    if udp_rows:
        has_results = True
        print(f"\n  {c.GREEN}{c.BOLD}UDP: {len(udp_rows)} port(s):{c.RESET}\n")
        print_port_table(udp_rows)

    if not has_results:
        print(f"\n  {c.RED}No open ports found.{c.RESET}")

    total_scanned = tcp_scanned + udp_scanned
    open_count = sum(
        1 for row in tcp_rows + udp_rows if row.get("status") == "OPEN"
    )
    filtered_count = len(tcp_rows) + len(udp_rows) - open_count
    print(f"\n{c.CYAN}{'-' * 60}{c.RESET}")
    summary = (
        f"  Scanned: {total_scanned:,} ports "
        f"({tcp_scanned:,} TCP + {udp_scanned:,} UDP) | "
        f"Open: {open_count}"
    )
    if filtered_count:
        summary += f" | Filtered: {filtered_count}"
    summary += f" | Time: {duration}"
    print(summary)
    print(f"{c.CYAN}{'=' * 60}{c.RESET}\n")


def scan_all_ports(target, tcp_ports=None, udp_ports=None,
                   timeout=TIMEOUT, workers=MAX_WORKERS, show_progress=True,
                   identify=True, banner_timeout=DEFAULT_BANNER_TIMEOUT,
                   retries=DEFAULT_RETRIES, show_filtered=False):
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
        hostname=reverse_dns(resolved),
    )

    def dispatch(item):
        proto, port = item
        if proto == "TCP":
            return scan_tcp_port(
                resolved, port, timeout, proto="TCP", identify=identify,
                banner_timeout=banner_timeout, retries=retries,
                include_filtered=show_filtered,
            )
        return scan_udp_port(
            resolved, port, timeout, proto="UDP", identify=identify,
            retries=retries,
        )

    items = [("TCP", port) for port in tcp_ports]
    items += [("UDP", port) for port in udp_ports]

    start = time.time()
    results, interrupted = run_threaded_scan(
        dispatch, items, max_workers=workers, show_progress=show_progress
    )
    if interrupted:
        print(f"\n\n  {Color.YELLOW}Scan interrupted by user.{Color.RESET}")

    tcp_open = sorted((result for result in results if result["proto"] == "TCP"),
                      key=lambda entry: entry["port"])
    udp_open = sorted((result for result in results if result["proto"] == "UDP"),
                      key=lambda entry: entry["port"])

    attach_local_processes(tcp_open + udp_open, resolved, local_ip)
    duration = f"{time.time() - start:.1f}s"
    print_combined_results(tcp_open, udp_open, len(tcp_ports), len(udp_ports), duration)
    return tcp_open + udp_open


if __name__ == "__main__":
    target = input("Enter hostname or IP to scan: ").strip()
    if not target:
        print("No target specified.")
        sys.exit(1)
    scan_all_ports(target)
