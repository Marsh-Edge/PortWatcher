<p align="center">
  <h1 align="center">PortWatcher</h1>
  <p align="center">Advanced Network Port Scanner</p>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a>
  <img src="https://img.shields.io/badge/Python-3.6+-3776AB.svg" alt="Python 3.6+">
  <img src="https://img.shields.io/badge/Dependencies-Zero-brightgreen.svg" alt="Zero Dependencies">
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg" alt="Cross-Platform">
</p>

<p align="center">
  A comprehensive Python-based network port scanning tool that detects open ports on target hosts using multiple scanning protocols (TCP and UDP). Built with multi-threaded architecture for high-performance parallel scanning. Designed for network administrators, security professionals, and cybersecurity enthusiasts.
</p>

<p align="center">
  <a href="#-preview">Preview</a> &bull;
  <a href="#-about-the-project">About</a> &bull;
  <a href="#-installation">Installation</a> &bull;
  <a href="#-usage">Usage</a> &bull;
  <a href="#-license">License</a>
</p>

---

## Preview

<!-- TODO: Add terminal screenshot or GIF showing PortWatcher in action -->

```
? Please select a scanning protocol: (Use arrow keys)
  1) All Protocols - Scans all 65,535 TCP ports + common UDP
  2) TCP           - Scans common/important TCP ports
  3) UDP           - Scans UDP ports
  4) Exit

──────────────────────────────────────────────────
  Target IP   : 192.168.1.1
  Source IP   : 10.0.0.42
──────────────────────────────────────────────────

PORT      STATUS      SERVICE         PRODUCT
──────────────────────────────────────────────────────────
21        OPEN        FTP             vsftpd 3.0.5
22        OPEN        SSH             OpenSSH 9.6
80        OPEN        HTTP            nginx/1.24.0
443       OPEN        HTTPS           TLSv1.3 TLS_AES_256_GCM_SHA384
3306      OPEN        MySQL           MySQL 8.0.36
5432      FILTERED    PostgreSQL
8080      OPEN        HTTP            Apache-Coyote/1.1

Scanned 70 ports in 2.18 seconds
```

---

## Table of Contents

- [About the Project](#-about-the-project)
- [Why This Project?](#-why-this-project)
- [Features](#-features)
- [Tech Stack](#-tech-stack)
- [Project Structure](#-project-structure)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Usage](#-usage)
- [Commands](#-commands)
- [Scanned Services](#-scanned-services)
- [Performance](#-performance)
- [Roadmap](#-roadmap)
- [Contributing](#-contributing)
- [License](#-license)
- [Author](#-author)
- [Acknowledgments](#-acknowledgments)
- [FAQ](#-faq)

---

## About the Project

PortWatcher is a standalone CLI port scanner built entirely with Python's standard library. It identifies open ports and resolves service names on any target host using TCP and UDP scanning protocols. Service identification is layered: banner and protocol fingerprinting, a curated IANA-style table, and the operating system's own service database. For local targets it also maps each listening port to the process that owns it. The tool operates with a bounded multi-threaded architecture (200 concurrent workers by default) to deliver fast, real-time results with a polished terminal interface.

**Problem it solves:** Network professionals need a lightweight, zero-dependency scanner that can quickly inventory open ports across a target, identify running services, and work cross-platform without installation overhead.

**Target audience:**

- Network administrators verifying server configurations
- Security professionals conducting authorized audits
- Students learning socket programming and network protocols
- Penetration testers performing initial reconnaissance

---

## Why This Project?

| Differentiator | Details |
|----------------|---------|
| **Zero Dependencies** | Uses only Python standard library modules — no `pip install` required |
| **Multi-threaded** | 200 concurrent scanning threads with a bounded work queue |
| **Cross-platform** | Works on Windows, Linux, and macOS with automatic ANSI color support |
| **Dual Protocol** | Scans both TCP and UDP with protocol-specific probes |
| **Layered Service Detection** | Banner/version fingerprinting + curated table + OS service database |
| **Local Process Mapping** | Maps listening ports to the owning process when scanning this machine |
| **Instant Setup** | Clone and run — no virtual environment, no build steps |

---

## Features

| Feature | Description |
|---------|-------------|
| TCP Common Port Scanning | Scans 70+ common TCP ports associated with popular services |
| Full TCP Range Scanning | Scans all 65,535 TCP ports (1-65535) |
| UDP Port Scanning | Dedicated UDP scanning with protocol-specific probes (DNS, SNMP, NTP, IKE, SSDP, mDNS) |
| Combined Protocol Scanning | Simultaneous TCP (full range) + UDP (common ports) scanning |
| Multi-threaded Architecture | Bounded ThreadPoolExecutor with 200 concurrent workers for parallel scanning |
| Real-time Progress Bar | Thread-safe progress bar with percentage, count, and visual indicator |
| Layered Service Detection | Banner/version fingerprinting, curated IANA-style table, and OS service database |
| Banner and Version Capture | HTTP, HTTPS/TLS, SSH, FTP, SMTP, POP3, IMAP, MySQL, Redis, Memcached, VNC, RDP |
| Local Process Attribution | Maps listening ports to the owning process (Windows, Linux, macOS) |
| Unknown-Port Resolution | Identifies services running on non-standard ports via active probes |
| Retry Support | Optional retries for timed-out TCP/UDP ports on lossy links |
| Filtered Port Reporting | Optional `--show-filtered` output for TCP ports that do not respond |
| Hostname Resolution | Automatically resolves hostnames to IPv4 addresses |
| Local IP Detection | Detects the local outward-facing IP address |
| Colored Terminal Output | Full ANSI color support with Windows compatibility via `ctypes` |
| Interactive Menu System | Persistent command-line menu with colored prompts |
| Scan Results Summary | Formatted table with port, status, service, and duration |
| Graceful Interrupt Handling | Clean exit on Ctrl+C at multiple execution levels |
| Standalone Modules | Each scanner can be run independently outside the menu |
| Export to CSV/JSON | Save scan results to CSV or JSON files for further analysis |
| Scriptable CLI | Non-interactive scans with protocol, port-range, output, timeout, and worker flags |

---

## Tech Stack

| Component | Technology |
|-----------|------------|
| **Language** | Python 3.6+ |
| **Networking** | `socket` (TCP/UDP communication), `ssl` (TLS fingerprinting) |
| **Concurrency** | `concurrent.futures` (ThreadPoolExecutor), `threading` |
| **System** | `os`, `sys`, `ctypes` (Windows ANSI/process support), `subprocess` (local process tables) |
| **Display** | `time` (progress tracking), ANSI escape codes |
| **External Dependencies** | None |

---

## Project Structure

```
PortWatcher/
│
├── app.py                        # Main entry point with interactive menu
├── LICENSE                       # MIT License
├── README.md                     # Project documentation
├── .gitignore                    # Git ignore rules
│
├── tests/                        # Standard-library unit and integration tests
│   ├── test_app.py               # CLI parsing and export tests
│   ├── test_scanner.py           # Loopback TCP/UDP scanning tests
│   └── test_services.py          # Service and banner fingerprint tests
│
└── Protocols/
    ├── __init__.py               # Package initializer
    ├── config.py                 # Shared timeouts, worker and retry defaults
    ├── services.py               # Service maps, banners, UDP and process detection
    ├── utils.py                  # Shared utilities, colors, scan engine, export
    ├── Tcp.py                    # TCP scanner (common ports, threaded)
    ├── Udp.py                    # UDP scanner (common ports with probes, threaded)
    └── AllProtocol.py            # Combined scanner (all TCP + common UDP)
```

---

## Installation

### Prerequisites

- Python 3.6 or higher
- Network access to the target host
- Administrator/root privileges recommended for accurate scanning

### Steps

```bash
# Clone the repository
git clone https://github.com/Marsh-Edge/PortWatcher.git

# Navigate to the project directory
cd PortWatcher

# Run the application
python app.py
```

No virtual environment, no `pip install`, no configuration files required.

---

## Configuration

PortWatcher is configured via constants hardcoded in the source files. There are no environment variables or external configuration files.

| Constant | Value | File | Description |
|----------|-------|------|-------------|
| `DEFAULT_TIMEOUT` | `0.5` | `config.py` | Socket timeout in seconds per port |
| `DEFAULT_WORKERS` | `200` | `config.py` | Maximum concurrent scanning threads |
| `DEFAULT_RETRIES` | `0` | `config.py` | Extra attempts for timed-out ports |
| `DEFAULT_BANNER_TIMEOUT` | `0.75` | `config.py` | Banner/version probe timeout |
| `COMMON_TCP_PORTS` | 70+ ports | `utils.py` | Curated list of common TCP ports to scan |
| `COMMON_UDP_PORTS` | 24 ports | `utils.py` | Curated list of common UDP ports to scan |
| `TCP_SERVICES` | 120+ mappings | `services.py` | Curated TCP port-to-service-name table |
| `UDP_SERVICES` | 30+ mappings | `services.py` | Curated UDP port-to-service-name table |
| `UDP_PROBES` | 6 probes | `utils.py` | Binary probe payloads for UDP services |

To customize scanning behavior, edit these constants directly in the respective source files. When using the CLI, `--timeout`, `--banner-timeout`, `--workers`, `--retries`, and `-r/--range` override the corresponding defaults for that run without editing the source.

---

## Usage

### Interactive Menu

```bash
python app.py
```

1. Launch the application
2. Select a scanning protocol from the menu
3. Enter a target hostname or IP address
4. View real-time scanning results
5. Review the results summary
6. Choose to return to the menu or exit

### Menu Options

```
1. All Protocols     — Scans all 65,535 TCP ports + common UDP ports
2. TCP               — Scans 70+ common TCP ports
3. UDP               — Scans common UDP ports with protocol-specific probes
4. Exit              — Closes the application
```

### Command-Line Interface

Scans can also be run non-interactively for scripting and automation. Passing a
target skips the menu:

```bash
# Scan common TCP ports on a target
python app.py 192.168.1.1

# Scan specific ports / ranges (TCP is the default protocol)
python app.py 192.168.1.1 -r 22,80,443,8000-8100

# UDP scan
python app.py 192.168.1.1 -p udp

# Full TCP (1-65535) + common UDP scan
python app.py 192.168.1.1 -p all

# Export results to CSV or JSON
python app.py 192.168.1.1 -r 1-1024 -o results.csv
python app.py 192.168.1.1 -p udp -o results.json

# Tune timeout, banner probe, concurrency and retries
python app.py 192.168.1.1 --timeout 1.0 --banner-timeout 1.5 --workers 300 --retries 1

# Skip banner probing, or include filtered TCP ports
python app.py 192.168.1.1 --no-identify
python app.py 192.168.1.1 -r 1-1024 --show-filtered
```

| Flag | Description |
|------|-------------|
| `<target>` | Target hostname or IP. Omit to launch the interactive menu |
| `-p, --protocol` | `tcp` (default), `udp`, or `all` |
| `-r, --range` | Ports to scan: `22,80,443` or `1-1000` (defaults to common ports; for `all` it applies to the TCP range) |
| `-o, --output` | Export results to a `.csv` or `.json` file |
| `--timeout` | Per-port socket timeout in seconds (default `0.5`) |
| `--banner-timeout` | Banner/version probe timeout in seconds (default `0.75`) |
| `--workers` | Maximum concurrent scanning threads (default `200`) |
| `--retries` | Extra attempts for timed-out ports (default `0`) |
| `--no-identify` | Skip banner/version detection on open ports |
| `--show-filtered` | Include filtered TCP ports in results |
| `--no-color` | Disable colored output (auto-disabled when stdout is not a terminal) |
| `--no-progress` | Disable the progress bar (auto-disabled when stdout is not a terminal) |
| `-v, --version` | Show version and exit |

Exported results are sorted by protocol and port for stable, diff-friendly output.

### Individual Modules

Each scanner can also be run standalone:

```bash
# TCP scanner only
python Protocols/Tcp.py

# UDP scanner only
python Protocols/Udp.py

# Combined full scan
python Protocols/AllProtocol.py
```

Each will prompt for a target hostname or IP when run independently.

---

## Commands

| Command | Description |
|---------|-------------|
| `python app.py` | Launch the interactive scanner menu |
| `python app.py <target>` | Scan common TCP ports on a target |
| `python app.py <target> -p udp` | Scan common UDP ports on a target |
| `python app.py <target> -p all` | Scan all TCP (1-65535) + common UDP ports |
| `python app.py <target> -r 22,80,443` | Scan a custom list or range of ports |
| `python app.py <target> -o results.csv` | Export results to CSV or JSON |
| `python app.py <target> --no-identify` | Skip banner/version probing |
| `python app.py <target> --show-filtered` | Include filtered TCP ports |
| `python app.py <target> --retries 1` | Retry timed-out ports once |
| `python -m unittest discover -s tests` | Run the test suite |
| `python Protocols/Tcp.py` | Run TCP common port scan directly |
| `python Protocols/Udp.py` | Run UDP common port scan directly |
| `python Protocols/AllProtocol.py` | Run full TCP (1-65535) + UDP scan directly |

---

## Service Identification

When a port is open, PortWatcher resolves its service using three layers, stopping at the first confident match:

1. **Banner and protocol fingerprinting** — probes the open port and reads its response. Supported families include HTTP/HTTPS, TLS, SSH, FTP, SMTP, POP3, IMAP, MySQL, Redis, Memcached, VNC, RDP, and generic text banners. This is what identifies services running on non-standard ports.
2. **Curated service table** — 120+ TCP and 30+ UDP mappings for well-known services.
3. **Operating system service database** — `socket.getservbyport()` reads the local OS service registry (for example `epmap` → MSRPC, `microsoft-ds` → SMB).

If all three layers fail, the port is reported as `Unknown`; if a banner was still captured, its text is shown in the `Product` column.

### Local process attribution

When the target is this machine or a loopback address, PortWatcher also maps each listening port to the process that owns it:

| Platform | Source |
|----------|--------|
| Windows | `netstat -ano` + `QueryFullProcessImageNameW` |
| Linux | `/proc/net/{tcp,udp}` + `/proc/<pid>/fd` |
| macOS | `lsof -nP -iTCP -iUDP` |

Process mapping is only possible for local targets. Remote hosts are identified through banners and the service tables above.

### Result fields

Each result contains `port`, `status`, `service`, and `confidence` (`high` for banner matches, `medium` for OS/table matches, `low` for port-number-only matches). `product`, `banner`, `process`, `pid`, and `proto` are added when available.

---

## Scanned Services

### TCP Common Ports

| Port | Service | Port | Service |
|------|---------|------|---------|
| 21 | FTP | 3306 | MySQL |
| 22 | SSH | 3389 | RDP |
| 23 | Telnet | 5432 | PostgreSQL |
| 25 | SMTP | 5900 | VNC |
| 53 | DNS | 6379 | Redis |
| 80 | HTTP | 8080 | HTTP-Proxy |
| 443 | HTTPS | 8443 | HTTPS-Alt |
| 993 | IMAPS | 27017 | MongoDB |

### UDP Common Ports

| Port | Service | Probe Type |
|------|---------|------------|
| 53 | DNS | DNS version/bind query |
| 123 | NTP | Standard NTP client request |
| 161 | SNMP | SNMP v1 GET request |
| 500 | IKE | ISAKMP header |
| 1900 | SSDP | UPnP M-SEARCH |
| 5353 | mDNS | mDNS query |

---

## Performance

| Scan Type | Estimated Time | Details |
|-----------|---------------|---------|
| TCP Common Ports | 2-5 seconds | 70+ ports, 200 threads, 0.5s timeout |
| UDP Common Ports | 5-10 seconds | 24 ports with protocol probes |
| Full TCP Range + UDP | 2-5 minutes | 65,535 TCP ports + common UDP |

**Notes:**
- Timing is network-dependent and varies with latency and firewall rules
- The thread pool keeps only a bounded number of futures in flight, which lowers memory use and makes Ctrl+C responsive
- Each port is tested with a 0.5-second socket timeout by default
- Banner probing only runs against ports that are already open

---

## Roadmap

### Completed

- [x] TCP common port scanning with service detection
- [x] Full TCP range scanning (1-65535)
- [x] UDP port scanning with protocol-specific probes
- [x] Multi-threaded architecture with bounded work queue (200 workers)
- [x] Real-time thread-safe progress bar
- [x] Interactive CLI menu system with colored output
- [x] Hostname resolution and local IP detection
- [x] Cross-platform support (Windows, Linux, macOS)
- [x] Windows ANSI color support via `ctypes`
- [x] Export results to CSV/JSON format
- [x] Banner grabbing and version detection
- [x] OS service database lookup for unknown ports
- [x] Local process attribution (port → PID → process)
- [x] Optional retries and filtered-port reporting
- [x] Standard-library test suite

### Planned

- [ ] GUI interface using tkinter or PyQt
- [ ] Ping sweep before port scanning
- [ ] Firewall detection and bypass techniques
- [ ] Configuration file support (`.ini` / `.yaml`)
- [ ] IPv6 support
- [ ] Host discovery (network enumeration)

---

## Contributing

Contributions are welcome. To contribute:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Commit your changes (`git commit -m "Add your feature"`)
4. Push to the branch (`git push origin feature/your-feature`)
5. Open a Pull Request

Please ensure your code follows the existing style and includes appropriate error handling.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for full details.

---

## Author

**Marsh** — [@Marsh-Edge](https://github.com/Marsh-Edge)

Contributors:
- **zen** — [zen.fawzan@gmail.com](mailto:zen.fawzan@gmail.com)

---

## Acknowledgments

- Python `socket` documentation for low-level networking reference
- Python `concurrent.futures` for accessible thread pool management
- The network security and open-source community for educational resources and inspiration

---

## FAQ

<details>
<summary><strong>Do I need administrator/root privileges?</strong></summary>

Recommended but not required. Some scanning operations (especially raw socket operations and certain UDP probes) may need elevated privileges for accurate results.
</details>

<details>
<summary><strong>Why does UDP scanning take longer than TCP?</strong></summary>

UDP is connectionless, so the scanner must send probes and wait for responses or timeouts. TCP scanning uses `connect_ex()` which completes the handshake quickly. UDP also requires protocol-specific probes rather than a simple connection attempt.
</details>

<details>
<summary><strong>What does "OPEN|FILTERED" mean?</strong></summary>

When a UDP port returns no response and times out, the port status is reported as OPEN|FILTERED — meaning the port could be open (accepting but not responding) or filtered by a firewall that silently drops packets.
</details>

<details>
<summary><strong>Why does a port still show "Unknown"?</strong></summary>

PortWatcher tries three layers: banner/version fingerprinting, a curated service table, and the operating system service database. `Unknown` means the service did not respond to any probe, the port is not registered in the OS database, and it is not in the curated table. If a text banner was captured, it is still shown in the `Product` column.
</details>

<details>
<summary><strong>Can PortWatcher tell me which process owns a port?</strong></summary>

Yes, when the target is this machine or a loopback address. It maps the listening port to a PID and process name using `netstat`/`QueryFullProcessImageNameW` on Windows, `/proc` on Linux, and `lsof` on macOS. Remote hosts cannot be inspected this way; they are identified through banners and service tables.
</details>

<details>
<summary><strong>Does banner probing send data to the target?</strong></summary>

Only to ports that are already confirmed open. Probes are small, limited to a short timeout, and are never sent to closed or filtered ports. Use `--no-identify` to disable probing entirely.
</details>

<details>
<summary><strong>Can I scan targets on a different network?</strong></summary>

Yes, as long as you have network connectivity to the target (it's reachable from your machine). Enter any hostname or IP address as the target.
</details>

<details>
<summary><strong>How do I customize which ports are scanned?</strong></summary>

Use the `-r/--range` flag to scan a custom set (e.g. `python app.py <target> -r 22,80,443` or `-r 1-1000`). To change the defaults used by the interactive menu and when no range is given, edit the `COMMON_TCP_PORTS` and `COMMON_UDP_PORTS` lists in `Protocols/utils.py`.
</details>

<details>
<summary><strong>Is this tool safe to use?</strong></summary>

PortWatcher is intended for authorized use only. Only scan networks and systems you own or have explicit permission to scan. Unauthorized port scanning may be illegal in your jurisdiction.
</details>
