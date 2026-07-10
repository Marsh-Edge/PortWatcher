"""UDP port scanner with threading and service detection."""

import socket
import sys
import os
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from utils import (
    Color, UDP_SERVICES, UDP_PROBES, COMMON_UDP_PORTS,
    resolve_target, get_local_ip, print_banner, print_progress, print_results,
)

TIMEOUT = 0.5
MAX_WORKERS = 100


def scan_udp_port(target, port, timeout):
    """Scan a single UDP port. Returns dict with status or None."""
    service = UDP_SERVICES.get(port, "Unknown")
    probe = UDP_PROBES.get(port, b"\x00")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(probe, (target, port))
        except OSError:
            sock.close()
            return {"port": port, "status": "FILTERED", "service": service}
        try:
            data, addr = sock.recvfrom(1024)
            sock.close()
            return {"port": port, "status": "OPEN", "service": service}
        except socket.timeout:
            sock.close()
            return {"port": port, "status": "OPEN|FILTERED", "service": service}
        except ConnectionRefusedError:
            sock.close()
            return None
    except (socket.error, OSError):
        return None


def scan_udp_ports(target):
    """Scan common UDP ports on target. Returns list of open port dicts."""
    resolved = resolve_target(target)
    if not resolved:
        print(f"\n  {Color.RED}Error: Could not resolve '{target}'{Color.RESET}\n")
        return []

    local_ip = get_local_ip()
    ports = COMMON_UDP_PORTS
    print_banner(resolved, local_ip, "UDP", len(ports), "(common)")

    open_ports = []
    counter = [0]
    lock = threading.Lock()
    start = time.time()

    try:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {
                executor.submit(scan_udp_port, resolved, port, TIMEOUT): port
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
    print_results(open_ports, len(ports), "UDP", duration)
    return open_ports


if __name__ == "__main__":
    target = input("Enter hostname or IP to scan: ").strip()
    if not target:
        print("No target specified.")
        sys.exit(1)
    scan_udp_ports(target)
