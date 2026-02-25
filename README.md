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
  - `os` - For system operations and subprocess management
  - `sys` - For program control and exit handling

---

## 📋 Project Structure

```
PortWatcher/
│
├── app.py                          # Main application entry point with menu system
│
├── Protocols/
│   ├── Tcp.py                      # TCP port scanner (common ports)
│   ├── All-Protocol.py             # Comprehensive port scanner (all ports)
│   └── Udp.py                      # UDP port scanner
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
- **Process Management:** Uses `os.system()` to execute individual protocol scanners
- **Persistent Menu:** Returns to main menu after each scan for continuous operation
- **Error Handling:** Validates user input and handles invalid selections

### **Tcp.py - TCP Scanner**
- Scans **80+ common TCP ports** associated with popular services
- Fast scanning with 1-microsecond timeout
- Displays open ports in real-time
- Services covered: FTP, SSH, Telnet, HTTP, HTTPS, DNS, SMTP, MySQL, PostgreSQL, etc.

### **All-Protocol.py - Comprehensive Scanner**
- Scans **all 65,535 TCP ports** (0-65535)
- Comprehensive enumeration of all available ports
- Ideal for discovering non-standard services
- Warning: Takes longer time to complete

### **Udp.py - UDP Scanner**
- Scans UDP protocol ports
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

- **TCP Scanner:** ~1-2 minutes for all common ports
- **All Protocols Scanner:** 5-10 minutes for complete port range (65535 ports)
- **Timeout Setting:** 1 microsecond for fast enumeration
- **Network Dependent:** Speed varies based on network latency and firewall rules

---

## ⚠️ Important Disclaimer

**Ethical Usage:** This tool should only be used on networks and systems you own or have explicit permission to scan. Unauthorized port scanning may be illegal in your jurisdiction.

---

## 🎓 Learning Outcomes

By using and studying this project, you'll learn:

- ✅ Socket programming in Python
- ✅ Network communication protocols (TCP/UDP)
- ✅ Port scanning techniques
- ✅ Exception handling in network operations
- ✅ File I/O and system operations
- ✅ Interactive command-line interfaces
- ✅ Process management and subprocess execution

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

- [ ] Multi-threading support for faster scanning
- [ ] Service version detection
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
