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

PORT      STATUS      SERVICE
──────────────────────────────────────────────────
21        OPEN        FTP
22        OPEN        SSH
80        OPEN        HTTP
443       OPEN        HTTPS
3306      OPEN        MySQL
5432      FILTERED    PostgreSQL
8080      OPEN        HTTP Alt

Scanned 70 ports in 3.42 seconds
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

PortWatcher is a standalone CLI port scanner built entirely with Python's standard library. It identifies open ports and resolves service names on any target host using TCP and UDP scanning protocols. The tool operates with a multi-threaded architecture (100 concurrent workers) to deliver fast, real-time results with a polished terminal interface.

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
| **Multi-threaded** | 100 concurrent scanning threads for high throughput |
| **Cross-platform** | Works on Windows, Linux, and macOS with automatic ANSI color support |
| **Dual Protocol** | Scans both TCP and UDP with protocol-specific probes |
| **Service Detection** | Maps 60+ TCP ports and 24 UDP ports to human-readable service names |
| **Instant Setup** | Clone and run — no virtual environment, no build steps |

---

## Features

| Feature | Description |
|---------|-------------|
| TCP Common Port Scanning | Scans 70+ common TCP ports associated with popular services |
| Full TCP Range Scanning | Scans all 65,535 TCP ports (1-65535) |
| UDP Port Scanning | Dedicated UDP scanning with protocol-specific probes (DNS, SNMP, NTP, IKE, SSDP, mDNS) |
| Combined Protocol Scanning | Simultaneous TCP (full range) + UDP (common ports) scanning |
| Multi-threaded Architecture | ThreadPoolExecutor with 100 concurrent workers for parallel scanning |
| Real-time Progress Bar | Thread-safe progress bar with percentage, count, and visual indicator |
| Service Name Detection | Maps ports to known service names (HTTP, SSH, MySQL, etc.) |
| Hostname Resolution | Automatically resolves hostnames to IPv4 addresses |
| Local IP Detection | Detects the local outward-facing IP address |
| Colored Terminal Output | Full ANSI color support with Windows compatibility via `ctypes` |
| Interactive Menu System | Persistent command-line menu with colored prompts |
| Scan Results Summary | Formatted table with port, status, service, and duration |
| Graceful Interrupt Handling | Clean exit on Ctrl+C at multiple execution levels |
| Standalone Modules | Each scanner can be run independently outside the menu |
| Export to CSV/JSON | Save scan results to CSV or JSON files for further analysis |

---

## Tech Stack

| Component | Technology |
|-----------|------------|
| **Language** | Python 3.6+ |
| **Networking** | `socket` (TCP/UDP communication) |
| **Concurrency** | `concurrent.futures` (ThreadPoolExecutor), `threading` |
| **System** | `os`, `sys`, `ctypes` (Windows ANSI support) |
| **Display** | `time` (progress tracking) |
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
└── Protocols/
    ├── __init__.py               # Package initializer
    ├── utils.py                  # Shared utilities, colors, service maps, probes
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
| `TIMEOUT` | `0.5` | `Tcp.py`, `Udp.py`, `AllProtocol.py` | Socket timeout in seconds per port |
| `MAX_WORKERS` | `100` | `Tcp.py`, `Udp.py`, `AllProtocol.py` | Maximum concurrent scanning threads |
| `COMMON_TCP_PORTS` | 70+ ports | `utils.py` | Curated list of common TCP ports to scan |
| `COMMON_UDP_PORTS` | 24 ports | `utils.py` | Curated list of common UDP ports to scan |
| `TCP_SERVICES` | 60+ mappings | `utils.py` | TCP port-to-service-name dictionary |
| `UDP_SERVICES` | 24 mappings | `utils.py` | UDP port-to-service-name dictionary |
| `UDP_PROBES` | 6 probes | `utils.py` | Binary probe payloads for UDP services |

To customize scanning behavior, edit these constants directly in the respective source files.

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
| `python Protocols/Tcp.py` | Run TCP common port scan directly |
| `python Protocols/Udp.py` | Run UDP common port scan directly |
| `python Protocols/AllProtocol.py` | Run full TCP (1-65535) + UDP scan directly |

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
| 80 | HTTP | 8080 | HTTP Alt |
| 443 | HTTPS | 8443 | HTTPS Alt |
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
| TCP Common Ports | 2-5 seconds | 70+ ports, 100 threads, 0.5s timeout |
| UDP Common Ports | 5-10 seconds | 24 ports with protocol probes |
| Full TCP Range + UDP | 2-5 minutes | 65,535 TCP ports + common UDP |

**Notes:**
- Timing is network-dependent and varies with latency and firewall rules
- Thread-safe progress tracking ensures accurate real-time updates
- Each port is tested with a 0.5-second socket timeout

---

## Roadmap

### Completed

- [x] TCP common port scanning with service detection
- [x] Full TCP range scanning (1-65535)
- [x] UDP port scanning with protocol-specific probes
- [x] Multi-threaded architecture (100 concurrent workers)
- [x] Real-time thread-safe progress bar
- [x] Interactive CLI menu system with colored output
- [x] Hostname resolution and local IP detection
- [x] Cross-platform support (Windows, Linux, macOS)
- [x] Windows ANSI color support via `ctypes`
- [x] Export results to CSV/JSON format

### Planned

- [ ] GUI interface using tkinter or PyQt
- [ ] Ping sweep before port scanning
- [ ] Firewall detection and bypass techniques
- [ ] Banner grabbing capabilities
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
<summary><strong>Can I scan targets on a different network?</strong></summary>

Yes, as long as you have network connectivity to the target (it's reachable from your machine). Enter any hostname or IP address as the target.
</details>

<details>
<summary><strong>How do I customize which ports are scanned?</strong></summary>

Edit the `COMMON_TCP_PORTS` and `COMMON_UDP_PORTS` lists in `Protocols/utils.py`. You can add or remove port numbers to tailor the scan to your needs.
</details>

<details>
<summary><strong>Is this tool safe to use?</strong></summary>

PortWatcher is intended for authorized use only. Only scan networks and systems you own or have explicit permission to scan. Unauthorized port scanning may be illegal in your jurisdiction.
</details>
