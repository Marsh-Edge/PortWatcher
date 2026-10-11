"""TCP port scanner with threading and service detection."""

import sys
import os
import time
from functools import partial

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from utils import (
    Color, COMMON_TCP_PORTS, scan_tcp_port,
    resolve_target, get_local_ip, print_banner, print_results,
    run_threaded_scan,
)

TIMEOUT = 0.5
MAX_WORKERS = 100


def scan_tcp_ports(target, ports=None, timeout=TIMEOUT, workers=MAX_WORKERS):
    """Scan TCP ports on target. Returns list of open port dicts."""
    resolved = resolve_target(target)
    if not resolved:
        print(f"\n  {Color.RED}Error: Could not resolve '{target}'{Color.RESET}\n")
        return []

    custom = ports is not None
    if ports is None:
        ports = COMMON_TCP_PORTS

    local_ip = get_local_ip()
    print_banner(resolved, local_ip, "TCP", len(ports), "" if custom else "(common)")

    worker = partial(scan_tcp_port, resolved, timeout=timeout)
    start = time.time()
    open_ports, interrupted = run_threaded_scan(worker, ports, max_workers=workers)
    if interrupted:
        print(f"\n\n  {Color.YELLOW}Scan interrupted by user.{Color.RESET}")

    duration = f"{time.time() - start:.1f}s"
    print_results(open_ports, len(ports), "TCP", duration)
    return open_ports


if __name__ == "__main__":
    target = input("Enter hostname or IP to scan: ").strip()
    if not target:
        print("No target specified.")
        sys.exit(1)
    scan_tcp_ports(target)
