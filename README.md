# 🔍 PortWatcher - Advanced Network Port Scanner

A comprehensive Python-based network port scanning tool that detects open ports on target hosts using multiple scanning protocols. Designed for network administrators, security professionals, and cybersecurity enthusiasts.

---

## ✨ Features

- **🔹 TCP Port Scanning** - Scans common TCP ports (21, 22, 80, 443, 3306, 5432, etc.)
- **🔹 Comprehensive Port Scanning** - Scans all 65,535 TCP ports (0-65535)
- **🔹 UDP Protocol Support** - Dedicated UDP port scanning capability
- **🔹 Interactive Menu System** - User-friendly command-line interface with persistent menu
- **🔹 Real-time Results** - Displays open ports as they are discovered
- **🔹 Network Information Display** - Shows source and target IP address details
- **🔹 Hostname Resolution** - Automatically resolves hostnames to IP addresses

---

## 🛠️ Technologies Used

- **Language:** Python 3.x
- **Libraries:** 
  - `socket` - For network communication and port scanning
  - `concurrent.futures` - For parallel thread-based scanning
  - `threading` - For thread-safe progress tracking

---

## 📋 Project Structure

```
PortWatcher/
│
├── app.py                          # Main application entry point with menu system
│
├── Protocols/
│   ├── Tcp.py                      # TCP port scanner (common ports)
│   ├── Udp.py                      # UDP port scanner (common ports)
│   ├── AllProtocol.py              # Comprehensive scanner (all TCP + common UDP)
│   ├── utils.py                    # Shared utilities, colors, service maps
│   └── __init__.py                 # Package init
│
├── README.md                       # Project documentation
├── LICENSE                         # Project license
└── .gitignore                      # Git ignore configuration

```

---

## 🚀 How to Use

### 1. **Prerequisites**
- Python 3.6 or higher installed
- Administrator/Root privileges (recommended for accurate scanning)
- Network access to target host

### 2. **Running the Application**

```bash
# Navigate to the project directory
cd PortWatcher

# Run the main application
python app.py
```

### 3. **Main Menu Options**

```
Welcome to the Port Scanner App!
Please select a scanning protocol:

1. All Protocols     - Scans all 65,535 TCP ports
2. TCP               - Scans common/important TCP ports (~80 ports)
3. UDP               - Scans UDP ports
4. Exit              - Closes the application
```

### 4. **Example Workflow**

```
1. Run: python app.py
2. Select option (1-4)
3. Enter target hostname or IP address
4. Wait for scanning results
5. View open ports with status
6. Choose to return to menu or exit
```

---

## 🔧 Key Functions Explained

### **app.py - Main Application**
- **Menu System:** Provides interactive selection of scanning protocols
- **Direct Imports:** Calls scanner functions directly (no subprocess spawning)
- **Input Validation:** Validates hostnames/IPs before scanning
- **Colored UI:** ANSI-colored menu and prompts for better readability
- **Error Handling:** Graceful Ctrl+C handling and input validation

### **Tcp.py - TCP Scanner**
- Scans **70+ common TCP ports** associated with popular services
- **100 concurrent threads** for fast parallel scanning
- 0.5s timeout per port for reliable detection
- Service name detection (HTTP, SSH, MySQL, etc.)
- Colored output with progress bar and scan summary

### **AllProtocol.py - Comprehensive Scanner**
- Scans **all 65,535 TCP ports** (1-65535) concurrently with 100 threads
- Also scans common UDP ports simultaneously
- Service name detection for known ports
- Colored output with progress bar and scan summary
- Ideal for discovering non-standard services

### **Udp.py - UDP Scanner**
- Scans common UDP ports with targeted probes (DNS, SNMP, NTP, etc.)
- Threaded for speed, reports OPEN/OPEN|FILTERED/FILTERED status
- Complements TCP scanning for full port coverage

---

## 📊 Port Scanning Details

### Scanned Services (TCP Common Ports)

| Port | Service | Port | Service |
|------|---------|------|---------|
| 21   | FTP     | 3306 | MySQL   |
| 22   | SSH     | 5432 | PostgreSQL |
| 23   | Telnet  | 5900 | VNC     |
| 25   | SMTP    | 8080 | HTTP Alt |
| 53   | DNS     | 8443 | HTTPS Alt |
| 80   | HTTP    | 27017| MongoDB |
| 443  | HTTPS   | 6379 | Redis   |

---

## 💡 Use Cases

1. **Network Administration** - Verify open ports on your servers
2. **Security Auditing** - Identify exposed services and potential vulnerabilities
3. **Network Troubleshooting** - Diagnose connectivity issues
4. **Penetration Testing** - Initial reconnaissance phase
5. **Learning & Education** - Understand Socket programming and network concepts

---

## ⚡ Performance Notes

- **TCP Scanner:** ~2-5 seconds for common ports (100 threads, 0.5s timeout)
- **UDP Scanner:** ~5-10 seconds for common ports
- **All Protocols Scanner:** 2-5 minutes for full TCP range (65,535 ports) + common UDP
- **Threading:** 100 concurrent threads with 0.5s per-port timeout
- **Network Dependent:** Speed varies based on network latency and firewall rules

---

## ⚠️ Important Disclaimer

**Ethical Usage:** This tool should only be used on networks and systems you own or have explicit permission to scan. Unauthorized port scanning may be illegal in your jurisdiction.

---

## 🎓 Learning Outcomes

By using and studying this project, you'll learn:

- ✅ Socket programming in Python
- ✅ Network communication protocols (TCP/UDP)
- ✅ Port scanning techniques with service detection
- ✅ Concurrent programming with ThreadPoolExecutor
- ✅ Exception handling in network operations
- ✅ Thread-safe progress tracking
- ✅ Interactive command-line interfaces with colored output

---

## 🔐 Security Considerations

- Always obtain proper authorization before scanning networks
- Be aware of network policies and firewall rules
- Some organizations monitor port scanning activity
- Results may vary based on firewall configurations
- Consider using VPN/Proxy for sensitive scanning activities

---

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 👨‍💻 Author & Contribution

Created for learning and educational purposes. 

**Feel free to:**
- Fork the repository
- Report issues
- Suggest improvements
- Submit pull requests

---

## 🎯 Future Enhancements

- [x] Multi-threading support for faster scanning
- [x] Service name detection
- [x] UDP port scanning
- [ ] GUI interface using tkinter/PyQt
- [ ] Export results to CSV/JSON format
- [ ] Ping sweep before port scanning
- [ ] Firewall detection
- [ ] Banner grabbing capabilities
- [ ] Configuration file support

---

## 📞 Contact & Support

For questions or assistance with this project, feel free to reach out.

---

**Happy Scanning! 🚀**
