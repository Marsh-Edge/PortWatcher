"""TCP port scanner with threading and service detection."""

import socket
import sys
import os
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from utils import (
    Color, TCP_SERVICES, COMMON_TCP_PORTS,
    resolve_target, get_local_ip, print_banner, print_progress, print_results,
)

TIMEOUT = 0.5
MAX_WORKERS = 100


def scan_tcp_port(target, port, timeout):
    """Scan a single TCP port. Returns dict if open, None otherwise."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target, port))
        sock.close()
        if result == 0:
            return {"port": port, "status": "OPEN", "service": TCP_SERVICES.get(port, "Unknown")}
    except (socket.error, OSError):
        pass
    return None


def scan_tcp_ports(target):
    """Scan common TCP ports on target. Returns list of open port dicts."""
    resolved = resolve_target(target)
    if not resolved:
        print(f"\n  {Color.RED}Error: Could not resolve '{target}'{Color.RESET}\n")
        return []

    local_ip = get_local_ip()
    ports = COMMON_TCP_PORTS
    print_banner(resolved, local_ip, "TCP", len(ports), "(common)")

    open_ports = []
    counter = [0]
    lock = threading.Lock()
    start = time.time()

    try:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {
                executor.submit(scan_tcp_port, resolved, port, TIMEOUT): port
                for port in ports
            }
            for future in as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)
                with lock:
                    counter[0] += 1
                    print_progress(counter[0], len(ports))
    except KeyboardInterrupt:
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
