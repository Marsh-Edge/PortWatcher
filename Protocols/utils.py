"""Shared utilities for PortWatcher scanners."""

import os
import sys
import socket
import ctypes
import csv
import json
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

if os.name == "nt":
    try:
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 0x0007)
    except Exception:
        pass


class Color:
    """ANSI escape codes for colored terminal output."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"


TCP_SERVICES = {
    7: "Echo", 9: "Discard", 13: "Daytime", 21: "FTP", 22: "SSH",
    23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
    111: "RPCBind", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP",
    161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
    514: "Syslog", 515: "LPD", 554: "RTSP", 587: "Submission",
    631: "IPP", 636: "LDAPS", 873: "Rsync", 990: "FTPS", 993: "IMAPS",
    995: "POP3S", 1080: "SOCKS", 1433: "MSSQL", 1521: "Oracle",
    1720: "H.323", 1723: "PPTP", 1900: "SSDP", 2049: "NFS",
    3000: "Dev-Server", 3306: "MySQL", 3389: "RDP", 4444: "Metasploit",
    5000: "Flask", 5060: "SIP", 5061: "SIPS", 5432: "PostgreSQL",
    5555: "ADB", 5900: "VNC", 6379: "Redis", 6666: "IRC", 7777: "Oracle-JVM",
    8008: "HTTP-Alt", 8080: "Proxy", 8443: "HTTPS-Alt", 8888: "HTTP-Alt",
    9000: "PHP-FPM", 9001: "ETCD", 9300: "Elasticsearch",
    11211: "Memcached", 12345: "NetBus", 27017: "MongoDB",
    28017: "MongoDB-Web", 31337: "BackOrifice",
    49152: "Ephemeral", 49153: "Ephemeral", 49154: "Ephemeral",
    49155: "Ephemeral", 49156: "Ephemeral", 49157: "Ephemeral",
    50000: "SAP", 50070: "HDFS", 50090: "HDFS-Secondary",
}

UDP_SERVICES = {
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 88: "Kerberos",
    123: "NTP", 135: "MSRPC", 137: "NetBIOS-NS", 138: "NetBIOS-DGM",
    161: "SNMP", 389: "LDAP", 500: "IKE", 514: "Syslog", 520: "RIP",
    623: "IPMI", 1434: "MSSQL-Browser", 1900: "SSDP", 2049: "NFS",
    4500: "NAT-T", 5353: "mDNS", 5355: "LLMNR", 6379: "Redis",
    11211: "Memcached", 27017: "MongoDB",
}

UDP_PROBES = {
    53: b"\x00\x00\x10\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03",
    123: b"\x1b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    161: b"\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x00\x00\x00\x01\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00",
    500: b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x11\x22\x33\x44\x55\x66\x77\x88\x00\x00\x00\x00\x00\x00\x00\x00",
    1900: b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nST: upnp:rootdevice\r\nMX: 3\r\nMAN: \"ssdp:discover\"\r\n\r\n",
    5353: b"\x00\x00\x84\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x04_udp\x04_llmnr\x00\x00\x0c\x00\x01",
}

COMMON_TCP_PORTS = sorted([
    7, 9, 13, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161,
    389, 443, 445, 465, 514, 515, 554, 587, 631, 636, 873, 990, 993,
    995, 1080, 1433, 1521, 1720, 1723, 1900, 2049, 3000, 3001, 3306,
    3389, 4444, 5000, 5001, 5060, 5061, 5432, 5555, 5900, 6379, 6666,
    6667, 7777, 8008, 8080, 8081, 8443, 8888, 9000, 9001, 9300,
    11211, 12345, 27017, 31337, 49152, 49153, 49154, 49155, 49156,
    49157, 50000,
])

COMMON_UDP_PORTS = sorted([
    53, 67, 68, 69, 88, 123, 135, 137, 138, 161, 389, 500, 514, 520,
    623, 1434, 1900, 2049, 4500, 5353, 5355, 6379, 11211, 27017,
])


def resolve_target(target):
    """Resolve hostname/IP. Returns resolved IP string or None."""
    try:
        socket.inet_pton(socket.AF_INET, target)
        return target
    except (socket.error, OSError):
        pass
    try:
        info = socket.getaddrinfo(target, None, socket.AF_INET)
        return info[0][4][0]
    except (socket.gaierror, IndexError):
        return None


def get_local_ip():
    """Get local outward-facing IP."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def scan_tcp_port(target, port, timeout, proto=None):
    """Scan a single TCP port. Returns dict if open, None otherwise."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target, port))
        sock.close()
        if result == 0:
            entry = {
                "port": port,
                "status": "OPEN",
                "service": TCP_SERVICES.get(port, "Unknown"),
            }
            if proto:
                entry["proto"] = proto
            return entry
    except (socket.error, OSError):
        pass
    return None


def _udp_entry(port, status, service, proto):
    entry = {"port": port, "status": status, "service": service}
    if proto:
        entry["proto"] = proto
    return entry


def scan_udp_port(target, port, timeout, proto=None):
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
            return _udp_entry(port, "FILTERED", service, proto)
        try:
            sock.recvfrom(1024)
            sock.close()
            return _udp_entry(port, "OPEN", service, proto)
        except socket.timeout:
            sock.close()
            return _udp_entry(port, "OPEN|FILTERED", service, proto)
        except ConnectionRefusedError:
            sock.close()
            return None
    except (socket.error, OSError):
        return None


def run_threaded_scan(worker, items, max_workers=100, show_progress=True):
    """Run ``worker(item)`` for each item concurrently.

    Returns ``(results, interrupted)`` where ``results`` contains every
    non-None worker return value collected before completion.
    """
    results = []
    counter = [0]
    lock = threading.Lock()
    total = len(items)
    executor = ThreadPoolExecutor(max_workers=max_workers)
    futures = []
    interrupted = False
    try:
        futures = [executor.submit(worker, item) for item in items]
        for future in as_completed(futures):
            result = future.result()
            if result:
                results.append(result)
            with lock:
                counter[0] += 1
                if show_progress and total:
                    print_progress(counter[0], total)
    except KeyboardInterrupt:
        interrupted = True
        for future in futures:
            future.cancel()
    finally:
        if interrupted:
            try:
                executor.shutdown(wait=False, cancel_futures=True)
            except TypeError:
                executor.shutdown(wait=False)
        else:
            executor.shutdown(wait=True)
    return results, interrupted


def print_banner(target_ip, local_ip, protocol, port_count, scan_type=""):
    """Print formatted scan header."""
    c = Color
    print()
    print(f"{c.CYAN}{'=' * 60}{c.RESET}")
    print(f"{c.BOLD}{c.CYAN}  PortWatcher - {protocol} Scanner{c.RESET}")
    print(f"{c.CYAN}{'=' * 60}{c.RESET}")
    print(f"  {c.DIM}Source:{c.RESET}      {local_ip}")
    print(f"  {c.DIM}Target:{c.RESET}      {target_ip}")
    print(f"  {c.DIM}Protocol:{c.RESET}    {protocol}")
    print(f"  {c.DIM}Port range:{c.RESET}  {port_count:,} ports {scan_type}")
    print(f"{c.CYAN}{'-' * 60}{c.RESET}")
    print(f"  {c.DIM}Press Ctrl+C to stop scanning{c.RESET}")
    print()


def print_progress(current, total):
    """Print a progress bar on the current line."""
    pct = (current / total) * 100
    width = 30
    filled = int(width * current / total)
    bar = "#" * filled + "-" * (width - filled)
    sys.stdout.write(
        f"\r  {Color.CYAN}[{bar}]{Color.RESET} {pct:5.1f}% "
        f"({current:,}/{total:,})"
    )
    sys.stdout.flush()


def print_port_table(rows):
    """Print a Port/Status/Service table for the given result rows."""
    c = Color
    print(f"  {'Port':>7}  {'Status':<16}  Service")
    print(f"  {'-' * 7}  {'-' * 16}  {'-' * 20}")
    for p in rows:
        status_color = c.GREEN if p["status"] == "OPEN" else c.YELLOW
        print(
            f"  {c.WHITE}{p['port']:>7}{c.RESET}  "
            f"{status_color}{p['status']:<16}{c.RESET}  "
            f"{c.DIM}{p['service']}{c.RESET}"
        )


def print_results(open_ports, total_scanned, protocol, duration):
    """Print formatted single-protocol scan results."""
    c = Color
    open_ports.sort(key=lambda x: x["port"])

    print()
    print(f"{c.CYAN}{'=' * 60}{c.RESET}")
    print(f"{c.BOLD}  Results - {protocol}{c.RESET}")
    print(f"{c.CYAN}{'=' * 60}{c.RESET}")

    if open_ports:
        print(f"\n  {c.GREEN}{c.BOLD}{len(open_ports)} open port(s) found:{c.RESET}\n")
        print_port_table(open_ports)
    else:
        print(f"\n  {c.RED}No open ports found.{c.RESET}")

    print(f"\n{c.CYAN}{'-' * 60}{c.RESET}")
    print(
        f"  Scanned: {total_scanned:,} ports | "
        f"Open: {len(open_ports)} | "
        f"Time: {duration}"
    )
    print(f"{c.CYAN}{'=' * 60}{c.RESET}\n")


_FILENAME_ILLEGAL = '\\/:*?"<>|'


def sanitize_filename(filepath):
    """Strip characters that are illegal in filenames, preserving directories."""
    parent, name = os.path.split(filepath)
    cleaned = "".join(
        "_" if ch in _FILENAME_ILLEGAL else ch for ch in name
    ).strip() or "portwatcher_scan"
    return os.path.join(parent, cleaned) if parent else cleaned


def _prepare_path(filepath):
    """Ensure the parent directory of ``filepath`` exists."""
    parent = os.path.dirname(os.path.abspath(filepath))
    if parent:
        os.makedirs(parent, exist_ok=True)


def export_to_csv(results, filepath):
    """Export scan results to a CSV file."""
    if not results:
        return False
    try:
        _prepare_path(filepath)
        fieldnames = ["port", "status", "service"]
        if any("proto" in r for r in results):
            fieldnames.append("proto")
        with open(filepath, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(results)
        return True
    except Exception as e:
        print(f"\n  {Color.RED}Export failed: {e}{Color.RESET}")
        return False


def export_to_json(results, filepath):
    """Export scan results to a JSON file."""
    if not results:
        return False
    try:
        _prepare_path(filepath)
        with open(filepath, "w") as f:
            json.dump(results, f, indent=2)
        return True
    except Exception as e:
        print(f"\n  {Color.RED}Export failed: {e}{Color.RESET}")
        return False


def prompt_export(results):
    """Prompt user to export scan results to CSV or JSON."""
    if not results:
        return

    c = Color
    choice = input(
        f"  {c.CYAN}>{c.RESET} Export results to file? (y/n): "
    ).strip().lower()
    if choice != "y":
        return

    print()
    print(f"  {c.WHITE}1{c.RESET}. CSV")
    print(f"  {c.WHITE}2{c.RESET}. JSON")
    fmt = input(f"  {c.CYAN}>{c.RESET} Select format (1-2): ").strip()

    if fmt == "1":
        ext = ".csv"
        export_fn = export_to_csv
    elif fmt == "2":
        ext = ".json"
        export_fn = export_to_json
    else:
        print(f"\n  {c.RED}Invalid format.{c.RESET}")
        return

    default_name = f"portwatcher_scan{ext}"
    filename = input(
        f"  {c.CYAN}>{c.RESET} Filename [{default_name}]: "
    ).strip()
    if not filename:
        filename = default_name

    if not filename.endswith(ext):
        filename += ext

    filename = sanitize_filename(filename)

    print()
    if export_fn(results, filename):
        print(f"  {c.GREEN}Results exported to {filename}{c.RESET}\n")
