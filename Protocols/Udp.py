"""UDP port scanner with threading and service detection."""

import sys
import os
import time
from functools import partial

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from utils import (
    Color, COMMON_UDP_PORTS, scan_udp_port, DEFAULT_TIMEOUT, DEFAULT_WORKERS,
    DEFAULT_RETRIES, resolve_target, get_local_ip, print_banner,
    print_results, run_threaded_scan, reverse_dns, attach_local_processes,
)

TIMEOUT = DEFAULT_TIMEOUT
MAX_WORKERS = DEFAULT_WORKERS


def scan_udp_ports(target, ports=None, timeout=TIMEOUT, workers=MAX_WORKERS,
                   show_progress=True, identify=True, retries=DEFAULT_RETRIES):
    """Scan UDP ports on target. Returns list of result dicts."""
    resolved = resolve_target(target)
    if not resolved:
        print(f"\n  {Color.RED}Error: Could not resolve '{target}'{Color.RESET}\n")
        return []

    custom = ports is not None
    if ports is None:
        ports = COMMON_UDP_PORTS

    local_ip = get_local_ip()
    print_banner(
        resolved, local_ip, "UDP", len(ports), "" if custom else "(common)",
        hostname=reverse_dns(resolved),
    )

    worker = partial(
        scan_udp_port, resolved, timeout=timeout, identify=identify,
        retries=retries,
    )
    start = time.time()
    open_ports, interrupted = run_threaded_scan(
        worker, ports, max_workers=workers, show_progress=show_progress
    )
    if interrupted:
        print(f"\n\n  {Color.YELLOW}Scan interrupted by user.{Color.RESET}")

    open_ports.sort(key=lambda entry: entry["port"])
    attach_local_processes(open_ports, resolved, local_ip)
    duration = f"{time.time() - start:.1f}s"
    print_results(open_ports, len(ports), "UDP", duration)
    return open_ports


if __name__ == "__main__":
    target = input("Enter hostname or IP to scan: ").strip()
    if not target:
        print("No target specified.")
        sys.exit(1)
    scan_udp_ports(target)
