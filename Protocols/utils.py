"""Shared utilities for PortWatcher scanners."""

import os
import sys
import csv
import json
import errno
import socket
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED

try:  # package import
    from .config import (
        DEFAULT_TIMEOUT, DEFAULT_WORKERS, DEFAULT_RETRIES,
        DEFAULT_BANNER_TIMEOUT, PENDING_PER_WORKER,
    )
    from .services import (
        TCP_SERVICES, UDP_SERVICES, lookup_service, grab_banner,
        fingerprint_udp_response, reverse_dns, attach_local_processes,
    )
except ImportError:  # direct script import (Protocols/ is on sys.path)
    from config import (
        DEFAULT_TIMEOUT, DEFAULT_WORKERS, DEFAULT_RETRIES,
        DEFAULT_BANNER_TIMEOUT, PENDING_PER_WORKER,
    )
    from services import (
        TCP_SERVICES, UDP_SERVICES, lookup_service, grab_banner,
        fingerprint_udp_response, reverse_dns, attach_local_processes,
    )

if os.name == "nt":
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 0x0007)
    except Exception:
        pass

__all__ = [
    "Color", "set_color_enabled", "TCP_SERVICES", "UDP_SERVICES",
    "COMMON_TCP_PORTS", "COMMON_UDP_PORTS", "UDP_PROBES",
    "DEFAULT_TIMEOUT", "DEFAULT_WORKERS", "DEFAULT_RETRIES",
    "DEFAULT_BANNER_TIMEOUT", "PENDING_PER_WORKER",
    "lookup_service", "grab_banner", "fingerprint_udp_response",
    "reverse_dns", "attach_local_processes", "resolve_target",
    "get_local_ip", "scan_tcp_port", "scan_udp_port", "run_threaded_scan",
    "print_banner", "print_progress", "print_port_table", "print_results",
    "sanitize_filename", "export_to_csv", "export_to_json", "prompt_export",
]


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


_COLOR_CODES = {
    name: getattr(Color, name)
    for name in ("RESET", "BOLD", "DIM", "RED", "GREEN", "YELLOW", "CYAN", "WHITE")
}


def set_color_enabled(enabled):
    """Enable or disable ANSI color output globally."""
    for name, code in _COLOR_CODES.items():
        setattr(Color, name, code if enabled else "")


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

# errno values for a definitively closed TCP port (POSIX and Winsock).
_CLOSED_ERRNOS = {111, 10061, getattr(errno, "ECONNREFUSED", 111)}


def resolve_target(target):
    """Resolve hostname/IP. Returns resolved IP string or None."""
    target = (target or "").strip()
    if not target:
        return None
    try:
        socket.inet_pton(socket.AF_INET, target)
        return target
    except (socket.error, OSError):
        pass
    try:
        info = socket.getaddrinfo(
            target, None, socket.AF_INET, socket.SOCK_STREAM)
        return info[0][4][0]
    except (socket.gaierror, IndexError, OSError):
        return None


def get_local_ip():
    """Get local outward-facing IP."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1)
        sock.connect(("8.8.8.8", 80))
        ip = sock.getsockname()[0]
        sock.close()
        return ip
    except Exception:
        return "127.0.0.1"


def _tcp_connect(target, port, timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        return sock.connect_ex((target, port))
    except (socket.error, OSError):
        return None
    finally:
        try:
            sock.close()
        except OSError:
            pass


def scan_tcp_port(target, port, timeout, proto=None, identify=True,
                  banner_timeout=None, retries=0, include_filtered=False):
    """Scan a single TCP port. Returns a result dict when relevant."""
    code = None
    for _ in range(retries + 1):
        code = _tcp_connect(target, port, timeout)
        if code == 0 or code in _CLOSED_ERRNOS:
            break

    proto_name = (proto or "tcp").lower()
    if code == 0:
        service, confidence = lookup_service(port, proto_name)
        entry = {
            "port": port,
            "status": "OPEN",
            "service": service,
            "confidence": confidence,
        }
        if proto:
            entry["proto"] = proto
        if identify:
            fingerprint = grab_banner(
                target, port,
                banner_timeout if banner_timeout is not None else DEFAULT_BANNER_TIMEOUT,
            )
            if fingerprint:
                if fingerprint.get("service"):
                    entry["service"] = fingerprint["service"]
                    entry["confidence"] = fingerprint.get("confidence", "high")
                if fingerprint.get("product"):
                    entry["product"] = fingerprint["product"]
                if fingerprint.get("banner"):
                    entry["banner"] = fingerprint["banner"]
        return entry

    if include_filtered and code not in _CLOSED_ERRNOS and code is not None:
        service, confidence = lookup_service(port, proto_name)
        entry = {
            "port": port,
            "status": "FILTERED",
            "service": service,
            "confidence": confidence,
        }
        if proto:
            entry["proto"] = proto
        return entry
    return None


def _udp_entry(port, status, service, proto, confidence="low"):
    entry = {
        "port": port,
        "status": status,
        "service": service,
        "confidence": confidence,
    }
    if proto:
        entry["proto"] = proto
    return entry


def scan_udp_port(target, port, timeout, proto=None, identify=True,
                  retries=0):
    """Scan a single UDP port. Returns a result dict with a status."""
    proto_name = (proto or "udp").lower()
    service, confidence = lookup_service(port, proto_name)
    probe = UDP_PROBES.get(port, b"\x00")

    sent_any = False
    for _ in range(retries + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            try:
                sock.sendto(probe, (target, port))
                sent_any = True
            except OSError:
                continue
            try:
                data, _ = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except (ConnectionRefusedError, ConnectionResetError):
                return None
            except OSError:
                return None
        finally:
            try:
                sock.close()
            except OSError:
                pass

        fingerprint = fingerprint_udp_response(data, port) if identify else None
        entry = _udp_entry(port, "OPEN", service, proto, confidence)
        if fingerprint:
            if fingerprint.get("service"):
                entry["service"] = fingerprint["service"]
            if fingerprint.get("product"):
                entry["product"] = fingerprint["product"]
            entry["confidence"] = fingerprint.get("confidence", "high")
        return entry

    if not sent_any:
        return _udp_entry(port, "FILTERED", service, proto, confidence)
    return _udp_entry(port, "OPEN|FILTERED", service, proto, confidence)


def run_threaded_scan(worker, items, max_workers=DEFAULT_WORKERS,
                      show_progress=True):
    """Run ``worker(item)`` for each item with bounded concurrency.

    Returns ``(results, interrupted)`` where ``results`` contains every
    non-None worker return value collected before completion.
    """
    results = []
    total = len(items)
    last_pct = [-1]
    counter = [0]
    executor = ThreadPoolExecutor(max_workers=max_workers)
    pending = set()
    item_iter = iter(items)
    interrupted = False

    def submit_next():
        try:
            item = next(item_iter)
        except StopIteration:
            return False
        pending.add(executor.submit(worker, item))
        return True

    try:
        for _ in range(min(total, max_workers * PENDING_PER_WORKER)):
            if not submit_next():
                break
        while pending:
            done, pending = wait(pending, return_when=FIRST_COMPLETED)
            for future in done:
                try:
                    result = future.result()
                except Exception:
                    result = None
                if result:
                    results.append(result)
                counter[0] += 1
                if show_progress and total:
                    pct = counter[0] * 100 // total
                    if pct != last_pct[0] or counter[0] == total:
                        last_pct[0] = pct
                        print_progress(counter[0], total)
            for _ in range(len(done)):
                submit_next()
    except KeyboardInterrupt:
        interrupted = True
        for future in pending:
            future.cancel()
    finally:
        if show_progress and total:
            _clear_progress_line()
        if interrupted:
            try:
                executor.shutdown(wait=False, cancel_futures=True)
            except TypeError:
                executor.shutdown(wait=False)
        else:
            executor.shutdown(wait=True)
    return results, interrupted


def print_banner(target_ip, local_ip, protocol, port_count, scan_type="",
                 hostname=None):
    """Print formatted scan header."""
    c = Color
    print()
    print(f"{c.CYAN}{'=' * 60}{c.RESET}")
    print(f"{c.BOLD}{c.CYAN}  PortWatcher - {protocol} Scanner{c.RESET}")
    print(f"{c.CYAN}{'=' * 60}{c.RESET}")
    print(f"  {c.DIM}Source:{c.RESET}      {local_ip}")
    print(f"  {c.DIM}Target:{c.RESET}      {target_ip}")
    if hostname and hostname != target_ip:
        print(f"  {c.DIM}Hostname:{c.RESET}    {hostname}")
    print(f"  {c.DIM}Protocol:{c.RESET}    {protocol}")
    range_line = f"{port_count:,} ports"
    if scan_type:
        range_line += f" {scan_type}"
    print(f"  {c.DIM}Port range:{c.RESET}  {range_line}")
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


def _clear_progress_line():
    """Erase the in-place progress bar so results print cleanly."""
    sys.stdout.write("\r" + " " * 100 + "\r")
    sys.stdout.flush()


def print_port_table(rows):
    """Print a Port/Status/Service table for the given result rows."""
    c = Color
    has_product = any(row.get("product") for row in rows)
    has_process = any(row.get("process") for row in rows)

    header = f"  {'Port':>7}  {'Status':<16}  {'Service':<20}"
    divider = f"  {'-' * 7}  {'-' * 16}  {'-' * 20}"
    if has_product:
        header += f"  {'Product':<28}"
        divider += f"  {'-' * 28}"
    if has_process:
        header += "  Process"
        divider += f"  {'-' * 20}"
    print(header)
    print(divider)

    for port in rows:
        status_color = c.GREEN if port["status"] == "OPEN" else c.YELLOW
        line = (
            f"  {c.WHITE}{port['port']:>7}{c.RESET}  "
            f"{status_color}{port['status']:<16}{c.RESET}  "
            f"{c.DIM}{port.get('service', 'Unknown'):<20}{c.RESET}"
        )
        if has_product:
            line += f"  {port.get('product') or '':<28}"
        if has_process:
            line += f"  {port.get('process') or ''}"
        print(line.rstrip())


def print_results(open_ports, total_scanned, protocol, duration):
    """Print formatted single-protocol scan results."""
    c = Color
    rows = sorted(open_ports, key=lambda item: item["port"])
    open_count = sum(1 for row in rows if row.get("status") == "OPEN")
    filtered_count = len(rows) - open_count

    print()
    print(f"{c.CYAN}{'=' * 60}{c.RESET}")
    print(f"{c.BOLD}  Results - {protocol}{c.RESET}")
    print(f"{c.CYAN}{'=' * 60}{c.RESET}")

    if rows:
        found = f"\n  {c.GREEN}{c.BOLD}{open_count} open port(s)"
        if filtered_count:
            found += f", {filtered_count} filtered"
        print(f"{found} found:{c.RESET}\n")
        print_port_table(rows)
    else:
        print(f"\n  {c.RED}No open ports found.{c.RESET}")

    print(f"\n{c.CYAN}{'-' * 60}{c.RESET}")
    print(
        f"  Scanned: {total_scanned:,} ports | "
        f"Open: {open_count} | "
        f"Time: {duration}"
    )
    print(f"{c.CYAN}{'=' * 60}{c.RESET}\n")


_FILENAME_ILLEGAL = '\\/:*?"<>|'
_FIELD_ORDER = [
    "port", "status", "service", "proto", "product", "process", "pid",
    "confidence", "banner",
]


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


def _sort_key(result):
    return (result.get("proto", ""), result["port"])


def _fieldnames(rows):
    present = set()
    for row in rows:
        present.update(row.keys())
    ordered = [field for field in _FIELD_ORDER if field in present]
    ordered.extend(sorted(present - set(ordered)))
    return ordered


def export_to_csv(results, filepath):
    """Export scan results to a CSV file."""
    if not results:
        return False
    try:
        _prepare_path(filepath)
        rows = sorted(results, key=_sort_key)
        with open(filepath, "w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(
                handle, fieldnames=_fieldnames(rows),
                extrasaction="ignore", restval="",
            )
            writer.writeheader()
            writer.writerows(rows)
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
        with open(filepath, "w", encoding="utf-8") as handle:
            json.dump(
                sorted(results, key=_sort_key), handle,
                indent=2, ensure_ascii=False,
            )
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
