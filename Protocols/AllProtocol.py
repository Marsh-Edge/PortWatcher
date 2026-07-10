"""Combined TCP and UDP scanner - scans all TCP ports (1-65535) + common UDP ports."""

import socket
import sys
import os
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from utils import (
    Color, TCP_SERVICES, UDP_SERVICES, UDP_PROBES, COMMON_UDP_PORTS,
    resolve_target, get_local_ip, print_progress,
)

TIMEOUT = 0.5
MAX_WORKERS = 100
ALL_TCP_PORTS = list(range(1, 65536))


def scan_tcp_port(target, port, timeout):
    """Scan a single TCP port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target, port))
        sock.close()
        if result == 0:
            return {"port": port, "status": "OPEN", "service": TCP_SERVICES.get(port, "Unknown"), "proto": "TCP"}
    except (socket.error, OSError):
        pass
    return None


def scan_udp_port(target, port, timeout):
    """Scan a single UDP port."""
    service = UDP_SERVICES.get(port, "Unknown")
    probe = UDP_PROBES.get(port, b"\x00")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(probe, (target, port))
        except OSError:
            sock.close()
            return {"port": port, "status": "FILTERED", "service": service, "proto": "UDP"}
        try:
            data, addr = sock.recvfrom(1024)
            sock.close()
            return {"port": port, "status": "OPEN", "service": service, "proto": "UDP"}
        except socket.timeout:
            sock.close()
            return {"port": port, "status": "OPEN|FILTERED", "service": service, "proto": "UDP"}
        except ConnectionRefusedError:
            sock.close()
            return None
    except (socket.error, OSError):
        return None


def print_combined_results(tcp_open, udp_open, tcp_scanned, udp_scanned, duration):
    """Print combined TCP + UDP scan results."""
    c = Color
    tcp_open.sort(key=lambda x: x["port"])
    udp_open.sort(key=lambda x: x["port"])

    print()
    print(f"{c.CYAN}{'=' * 60}{c.RESET}")
    print(f"{c.BOLD}  Results - All Protocols (TCP + UDP){c.RESET}")
    print(f"{c.CYAN}{'=' * 60}{c.RESET}")

    has_results = False

    if tcp_open:
        has_results = True
        print(f"\n  {c.GREEN}{c.BOLD}TCP: {len(tcp_open)} open port(s):{c.RESET}\n")
        print(f"  {'Port':>7}  {'Status':<16}  Service")
        print(f"  {'-' * 7}  {'-' * 16}  {'-' * 20}")
        for p in tcp_open:
            sc = c.GREEN if p["status"] == "OPEN" else c.YELLOW
            print(
                f"  {c.WHITE}{p['port']:>7}{c.RESET}  "
                f"{sc}{p['status']:<16}{c.RESET}  "
                f"{c.DIM}{p['service']}{c.RESET}"
            )

    if udp_open:
        has_results = True
        print(f"\n  {c.GREEN}{c.BOLD}UDP: {len(udp_open)} open port(s):{c.RESET}\n")
        print(f"  {'Port':>7}  {'Status':<16}  Service")
        print(f"  {'-' * 7}  {'-' * 16}  {'-' * 20}")
        for p in udp_open:
            sc = c.GREEN if p["status"] == "OPEN" else c.YELLOW
            print(
                f"  {c.WHITE}{p['port']:>7}{c.RESET}  "
                f"{sc}{p['status']:<16}{c.RESET}  "
                f"{c.DIM}{p['service']}{c.RESET}"
            )

    if not has_results:
        print(f"\n  {c.RED}No open ports found.{c.RESET}")

    total_scanned = tcp_scanned + udp_scanned
    total_open = len(tcp_open) + len(udp_open)
    print(f"\n{c.CYAN}{'-' * 60}{c.RESET}")
    print(
        f"  Scanned: {total_scanned:,} ports "
        f"({tcp_scanned:,} TCP + {udp_scanned:,} UDP) | "
        f"Open: {total_open} | Time: {duration}"
    )
    print(f"{c.CYAN}{'=' * 60}{c.RESET}\n")


def scan_all_ports(target):
    """Scan all TCP ports (1-65535) and common UDP ports. Returns combined list."""
    resolved = resolve_target(target)
    if not resolved:
        print(f"\n  {Color.RED}Error: Could not resolve '{target}'{Color.RESET}\n")
        return []

    local_ip = get_local_ip()
    tcp_ports = ALL_TCP_PORTS
    udp_ports = COMMON_UDP_PORTS
    total = len(tcp_ports) + len(udp_ports)

    c = Color
    print()
    print(f"{c.CYAN}{'=' * 60}{c.RESET}")
    print(f"{c.BOLD}{c.CYAN}  PortWatcher - All Protocols Scanner{c.RESET}")
    print(f"{c.CYAN}{'=' * 60}{c.RESET}")
    print(f"  {c.DIM}Source:{c.RESET}      {local_ip}")
    print(f"  {c.DIM}Target:{c.RESET}      {resolved}")
    print(f"  {c.DIM}TCP ports:{c.RESET}   {len(tcp_ports):,} (1-65535)")
    print(f"  {c.DIM}UDP ports:{c.RESET}   {len(udp_ports):,} (common)")
    print(f"  {c.DIM}Total:{c.RESET}       {total:,} ports")
    print(f"{c.CYAN}{'-' * 60}{c.RESET}")
    print(f"  {c.DIM}Press Ctrl+C to stop scanning{c.RESET}")
    print()

    tcp_open = []
    udp_open = []
    counter = [0]
    lock = threading.Lock()
    start = time.time()

    try:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {}
            for port in tcp_ports:
                futures[executor.submit(scan_tcp_port, resolved, port, TIMEOUT)] = "TCP"
            for port in udp_ports:
                futures[executor.submit(scan_udp_port, resolved, port, TIMEOUT)] = "UDP"

            for future in as_completed(futures):
                result = future.result()
                if result:
                    if result["proto"] == "TCP":
                        tcp_open.append(result)
                    else:
                        udp_open.append(result)
                with lock:
                    counter[0] += 1
                    print_progress(counter[0], total)
    except KeyboardInterrupt:
        print(f"\n\n  {c.YELLOW}Scan interrupted by user.{c.RESET}")

    duration = f"{time.time() - start:.1f}s"
    print_combined_results(tcp_open, udp_open, len(tcp_ports), len(udp_ports), duration)
    return tcp_open + udp_open


if __name__ == "__main__":
    target = input("Enter hostname or IP to scan: ").strip()
    if not target:
        print("No target specified.")
        sys.exit(1)
    scan_all_ports(target)
