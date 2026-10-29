"""Service identification helpers for PortWatcher.

Resolution order (highest confidence first):
1. Banner / protocol fingerprinting on open ports.
2. A curated IANA-style service table.
3. The operating system service database (``socket.getservbyport``).
4. Local process attribution (loopback scans only).
"""

import os
import re
import sys
import csv
import io
import socket
import subprocess
from functools import lru_cache

try:  # package import
    from .config import DEFAULT_BANNER_TIMEOUT, MAX_BANNER_BYTES
except ImportError:  # direct script import (Protocols/ is on sys.path)
    from config import DEFAULT_BANNER_TIMEOUT, MAX_BANNER_BYTES

try:
    import ssl
except ImportError:  # pragma: no cover - minimal Python builds
    ssl = None


TCP_SERVICES = {
    7: "Echo", 9: "Discard", 13: "Daytime", 20: "FTP-Data", 21: "FTP",
    22: "SSH", 23: "Telnet", 25: "SMTP", 37: "Time", 43: "Whois",
    53: "DNS", 70: "Gopher", 79: "Finger", 80: "HTTP", 81: "HTTP-Alt",
    82: "HTTP-Alt", 83: "HTTP-Alt", 84: "HTTP-Alt", 85: "HTTP-Alt",
    88: "Kerberos", 89: "Kerberos", 90: "Kerberos", 102: "ISO-TSAP",
    109: "POP2", 110: "POP3", 111: "RPCBind", 113: "Ident", 119: "NNTP",
    135: "MSRPC", 139: "NetBIOS", 143: "IMAP", 179: "BGP", 194: "IRC",
    389: "LDAP", 427: "SLP", 443: "HTTPS", 444: "SNPP", 445: "SMB",
    464: "Kerberos-PW", 465: "SMTPS", 512: "Rexec", 513: "Rlogin",
    514: "Syslog", 515: "LPD", 524: "Netware", 554: "RTSP",
    587: "Submission", 593: "MSRPC-HTTP", 623: "IPMI", 631: "IPP",
    636: "LDAPS", 646: "LDP", 873: "Rsync", 888: "HTTP-Alt",
    902: "VMware", 989: "FTPS-Data", 990: "FTPS", 993: "IMAPS",
    995: "POP3S", 1080: "SOCKS", 1099: "RMI", 1194: "OpenVPN",
    1311: "Dell-OpenManage", 1433: "MSSQL", 1521: "Oracle", 1701: "L2TP",
    1719: "PPTP", 1720: "H.323", 1723: "PPTP", 1755: "MMS",
    1812: "RADIUS", 1813: "RADIUS-Acct", 2000: "Cisco-SCCP",
    2049: "NFS", 2121: "FTP-Alt", 2181: "ZooKeeper", 2222: "SSH-Alt",
    2323: "Telnet-Alt", 2375: "Docker", 2376: "Docker-TLS",
    3000: "Dev-Server", 3001: "Dev-Server", 3128: "Squid", 3260: "iSCSI",
    3268: "LDAP-GC", 3269: "LDAPS-GC", 3306: "MySQL", 3389: "RDP",
    3478: "STUN", 3479: "STUN", 3690: "SVN", 4000: "Dev-Server",
    4369: "Erlang-EPMD", 4443: "HTTPS-Alt", 4444: "Metasploit",
    4500: "NAT-T", 4505: "Salt", 4506: "Salt", 5000: "Flask",
    5001: "Dev-Server", 5060: "SIP", 5061: "SIPS", 5222: "XMPP",
    5269: "XMPP-Server", 5357: "WSD", 5432: "PostgreSQL", 5555: "ADB",
    5601: "Kibana", 5672: "RabbitMQ", 5683: "CoAP", 5900: "VNC",
    5901: "VNC", 5938: "TeamViewer", 5984: "CouchDB", 6000: "X11",
    6379: "Redis", 6443: "Kubernetes-API", 6660: "IRC", 6666: "IRC",
    6667: "IRC", 7001: "WebLogic", 7002: "WebLogic-SSL",
    7070: "HTTP-Alt", 8000: "HTTP-Alt", 8008: "HTTP-Alt", 8009: "AJP",
    8080: "HTTP-Proxy", 8081: "HTTP-Alt", 8082: "HTTP-Alt",
    8088: "HTTP-Alt", 8090: "HTTP-Alt", 8123: "HTTP-Alt",
    8161: "ActiveMQ", 8200: "Vault", 8443: "HTTPS-Alt", 8500: "Consul",
    8888: "HTTP-Alt", 8983: "Solr", 9000: "PHP-FPM", 9001: "Supervisor",
    9042: "Cassandra", 9090: "HTTP-Alt", 9092: "Kafka",
    9200: "Elasticsearch", 9300: "Elasticsearch-Transport", 9418: "Git",
    9443: "HTTPS-Alt", 10000: "Webmin", 10250: "Kubelet",
    11211: "Memcached", 12345: "NetBus", 15672: "RabbitMQ-Mgmt",
    16379: "Redis", 27017: "MongoDB", 27018: "MongoDB",
    28017: "MongoDB-Web", 31337: "BackOrifice", 50000: "SAP",
    50070: "HDFS", 50090: "HDFS-Secondary", 61616: "ActiveMQ",
}

UDP_SERVICES = {
    53: "DNS", 67: "DHCP-Server", 68: "DHCP-Client", 69: "TFTP",
    88: "Kerberos", 111: "RPCBind", 123: "NTP", 135: "MSRPC",
    137: "NetBIOS-NS", 138: "NetBIOS-DGM", 161: "SNMP", 162: "SNMP-Trap",
    389: "LDAP", 427: "SLP", 443: "QUIC", 500: "IKE", 514: "Syslog",
    520: "RIP", 546: "DHCPv6-Client", 547: "DHCPv6-Server", 623: "IPMI",
    631: "IPP", 1194: "OpenVPN", 1434: "MSSQL-Browser", 1701: "L2TP",
    1812: "RADIUS", 1813: "RADIUS-Acct", 1900: "SSDP", 2049: "NFS",
    3478: "STUN", 3479: "STUN", 4500: "NAT-T", 4789: "VXLAN",
    51820: "WireGuard", 5353: "mDNS", 5355: "LLMNR", 5683: "CoAP",
    6379: "Redis", 11211: "Memcached", 27017: "MongoDB",
}

_SERVICE_ALIASES = {
    "domain": "DNS", "http": "HTTP", "https": "HTTPS", "ftp": "FTP",
    "ftp-data": "FTP-Data", "ssh": "SSH", "telnet": "Telnet",
    "smtp": "SMTP", "submission": "Submission", "pop3": "POP3",
    "imap": "IMAP", "imaps": "IMAPS", "pop3s": "POP3S", "ldap": "LDAP",
    "ldaps": "LDAPS", "kerberos": "Kerberos", "epmap": "MSRPC",
    "netbios-ssn": "NetBIOS", "netbios-ns": "NetBIOS-NS",
    "netbios-dgm": "NetBIOS-DGM", "microsoft-ds": "SMB",
    "ms-sql-s": "MSSQL", "ms-sql-m": "MSSQL-Browser",
    "ms-wbt-server": "RDP", "nfs": "NFS", "rpcbind": "RPCBind",
    "sunrpc": "RPCBind", "ntp": "NTP", "snmp": "SNMP",
    "snmptrap": "SNMP-Trap", "syslog": "Syslog", "ipp": "IPP",
    "rsync": "Rsync", "redis": "Redis", "mysql": "MySQL",
    "postgresql": "PostgreSQL", "mongodb": "MongoDB",
    "memcache": "Memcached", "memcached": "Memcached", "vnc": "VNC",
    "x11": "X11", "rtsp": "RTSP", "sip": "SIP", "sips": "SIPS",
    "xmpp-client": "XMPP", "xmpp-server": "XMPP-Server", "git": "Git",
    "svn": "SVN", "http-alt": "HTTP-Alt", "https-alt": "HTTPS-Alt",
    "http-proxy": "HTTP-Proxy", "zookeeper": "ZooKeeper",
    "kafka": "Kafka", "elasticsearch": "Elasticsearch",
    "tftp": "TFTP", "isakmp": "IKE", "ipmi": "IPMI", "stun": "STUN",
}

_HTTP_PORTS = frozenset({
    80, 81, 82, 83, 84, 85, 888, 3000, 3001, 4000, 5000, 5001, 5601,
    7001, 7070, 8000, 8008, 8080, 8081, 8082, 8088, 8090, 8123, 8161,
    8500, 8888, 8983, 9000, 9001, 9090, 9200, 10000, 15672, 28017,
    50070, 50090,
})

_TLS_PORTS = frozenset({
    443, 465, 636, 989, 990, 993, 995, 2376, 3269, 4443, 5061, 5986,
    6443, 7002, 8443, 9443,
})

_TLS_SERVICES = {
    443: "HTTPS", 465: "SMTPS", 636: "LDAPS", 989: "FTPS-Data",
    990: "FTPS", 993: "IMAPS", 995: "POP3S", 2376: "Docker-TLS",
    3269: "LDAPS-GC", 4443: "HTTPS-Alt", 5061: "SIPS",
    6443: "Kubernetes-API", 7002: "WebLogic-SSL", 8443: "HTTPS-Alt",
    9443: "HTTPS-Alt",
}

_REDIS_PORTS = frozenset({6379, 16379})
_MEMCACHED_PORTS = frozenset({11211})
_RDP_PORTS = frozenset({3389})


def normalize_service_name(name):
    """Normalize an OS/service name to a readable label."""
    if not name:
        return None
    key = name.strip().lower()
    if key in _SERVICE_ALIASES:
        return _SERVICE_ALIASES[key]
    cleaned = key.replace("_", "-")
    return "-".join(part.capitalize() for part in cleaned.split("-") if part) or name


@lru_cache(maxsize=8192)
def os_service_name(port, proto):
    """Return the operating system service name for a port/protocol."""
    try:
        return socket.getservbyport(port, proto)
    except (OSError, socket.error):
        return None


def lookup_service(port, proto):
    """Return ``(service_name, confidence)`` from curated and OS databases."""
    proto = (proto or "tcp").lower()
    table = TCP_SERVICES if proto == "tcp" else UDP_SERVICES
    curated = table.get(port)
    os_name = normalize_service_name(os_service_name(port, proto))
    if curated:
        return curated, "medium" if os_name else "low"
    if os_name:
        return os_name, "medium"
    return "Unknown", "low"


def _fp(service, product=None, banner=None, confidence="high"):
    return {
        "service": service,
        "product": product,
        "banner": banner,
        "confidence": confidence,
    }


def _decode(data):
    return data.decode("latin-1", "replace").strip("\x00\r\n ")


def _looks_text(data):
    if not data:
        return False
    sample = data[:512]
    printable = sum(32 <= b < 127 or b in (9, 10, 13) for b in sample)
    return printable / float(len(sample)) >= 0.85


def _header_value(text, name):
    for line in text.splitlines()[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            if key.strip().lower() == name:
                return value.strip()
    return None


def _mysql_version(data):
    if len(data) < 6:
        return None
    packet_len = data[0] | (data[1] << 8) | (data[2] << 16)
    if packet_len < 5 or data[4] != 0x0A:
        return None
    end = data.find(b"\x00", 5)
    if end <= 5:
        return None
    return data[5:end].decode("latin-1", "replace")


def fingerprint_banner(data, port=None):
    """Identify a service from raw bytes received from an open port."""
    if not data:
        return None
    head = data[:8192]

    if head[:2] == b"\x03\x00" and len(head) >= 11:
        return _fp("RDP", "RDP", _decode(head)[:256])
    if b"\xffSMB" in head[:16] or b"\xfeSMB" in head[:16]:
        return _fp("SMB", "SMB", None)
    if head[:1] == b"\x16" and len(head) > 2 and head[1] == 0x03:
        return _fp("TLS", "TLS", None, "medium")

    mysql_version = _mysql_version(head)
    if mysql_version:
        return _fp("MySQL", "MySQL " + mysql_version, _decode(head)[:256])

    text = _decode(head)
    upper = text.upper()

    if upper.startswith("HTTP/"):
        product = _header_value(text, "server")
        powered = _header_value(text, "x-powered-by")
        if powered and powered not in (product or ""):
            product = "%s (%s)" % (product, powered) if product else powered
        return _fp("HTTP", product, text[:256])

    if upper.startswith("SSH-"):
        line = text.splitlines()[0]
        parts = line.split("-", 2)
        software = parts[2] if len(parts) == 3 else line
        return _fp("SSH", software, line[:256])

    if upper.startswith("220"):
        line = text.splitlines()[0]
        if any(token in upper for token in ("FTP", "FILEZILLA", "VSFTPD",
                                            "PROFTPD", "PURE-FTPD")):
            return _fp("FTP", line[4:].strip() or None, line[:256])
        if any(token in upper for token in ("SMTP", "POSTFIX", "EXIM",
                                            "SENDMAIL", "MAIL")):
            return _fp("SMTP", line[4:].strip() or None, line[:256])
        if "RTSP" in upper:
            return _fp("RTSP", line[4:].strip() or None, line[:256])

    if upper.startswith("RTSP/"):
        return _fp("RTSP", _header_value(text, "server"), text[:256])
    if upper.startswith("+OK"):
        return _fp("POP3", text.splitlines()[0][:120], text[:256])
    if upper.startswith("* OK"):
        return _fp("IMAP", text.splitlines()[0][:120], text[:256])
    if upper.startswith("RFB "):
        return _fp("VNC", text.splitlines()[0], text[:256])
    if upper.startswith("+PONG") or upper.startswith("-NOAUTH"):
        return _fp("Redis", "Redis", text[:256])
    if upper.startswith("-ERR") and "UNKNOWN COMMAND" in upper:
        return _fp("Redis", "Redis", text[:256])
    if upper.startswith("VERSION "):
        return _fp("Memcached", text.splitlines()[0], text[:256])

    if _looks_text(head):
        first = next((line for line in text.splitlines() if line.strip()), "")
        return _fp(None, first[:120] or None, text[:256], "low")
    return None


def fingerprint_udp_response(data, port=None):
    """Identify a UDP service from a response payload."""
    if not data:
        return None

    if len(data) >= 12 and port in (53, 5353, 5355):
        flags = (data[2] << 8) | data[3]
        if flags & 0x8000:
            if port == 5353:
                return _fp("mDNS", "mDNS response", None)
            if port == 5355:
                return _fp("LLMNR", "LLMNR response", None)
            return _fp("DNS", "DNS response", None)

    if port == 123 and len(data) >= 48:
        return _fp("NTP", "NTP response", None)
    if data[:1] == b"\x30" and port in (161, 162):
        return _fp("SNMP", "SNMP response", None)

    text = _decode(data)
    upper = text.upper()
    if port == 1900 and ("HTTP/" in upper or "M-SEARCH" in upper
                         or "NOTIFY" in upper or "ST:" in upper):
        return _fp("SSDP", "SSDP response", None)
    if upper.startswith("HTTP/"):
        return _fp("HTTP", _header_value(text, "server"), None)

    service, _ = lookup_service(port, "udp") if port else ("Unknown", "low")
    if service != "Unknown":
        return _fp(service, "UDP response", None, "medium")
    return _fp(None, "UDP response", None, "low")


def _connect(host, port, timeout):
    return socket.create_connection((host, port), timeout=timeout)


def _close(sock):
    if sock is not None:
        try:
            sock.close()
        except OSError:
            pass


def _recv_some(sock, limit=MAX_BANNER_BYTES):
    try:
        return sock.recv(limit)
    except (socket.timeout, TimeoutError, OSError):
        return b""


def _is_ip(host):
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(family, host)
            return True
        except (OSError, ValueError):
            pass
    return False


def _try_passive(host, port, timeout):
    sock = None
    try:
        sock = _connect(host, port, timeout)
        sock.settimeout(min(timeout, 0.35))
        data = _recv_some(sock)
    except (OSError, socket.error):
        return None
    finally:
        _close(sock)
    return fingerprint_banner(data, port)


def _try_http(host, port, timeout):
    sock = None
    try:
        sock = _connect(host, port, timeout)
        sock.settimeout(timeout)
        request = (
            "HEAD / HTTP/1.0\r\nHost: %s\r\nUser-Agent: PortWatcher\r\n"
            "Connection: close\r\n\r\n" % host
        ).encode("latin-1", "replace")
        sock.sendall(request)
        data = _recv_some(sock)
    except (OSError, socket.error):
        return None
    finally:
        _close(sock)
    fingerprint = fingerprint_banner(data, port)
    if fingerprint and fingerprint.get("service") in ("HTTP", "RTSP"):
        return fingerprint
    return None


def _try_tls(host, port, timeout):
    if ssl is None:
        return None
    sock = None
    tls = None
    try:
        sock = _connect(host, port, timeout)
        sock.settimeout(timeout)
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        server_hostname = None if _is_ip(host) else host
        tls = context.wrap_socket(sock, server_hostname=server_hostname)
        version = tls.version() or "TLS"
        cipher = tls.cipher()
        product = version
        if cipher:
            product += " " + cipher[0]
        return _fp(_TLS_SERVICES.get(port, "TLS"), product, None)
    except (OSError, socket.error, ssl.SSLError):
        return None
    finally:
        _close(tls)
        if tls is None:
            _close(sock)


def _try_redis(host, port, timeout):
    sock = None
    try:
        sock = _connect(host, port, timeout)
        sock.settimeout(timeout)
        sock.sendall(b"PING\r\n")
        data = _recv_some(sock)
        if not data:
            return None
        upper = data.upper()
        if b"PONG" not in upper and b"NOAUTH" not in upper and not upper.startswith(b"-ERR"):
            return None
        product = "Redis"
        try:
            sock.sendall(b"INFO server\r\n")
            info = _recv_some(sock, 8192)
            match = re.search(rb"redis_version:([^\r\n]+)", info)
            if match:
                product = "Redis " + match.group(1).decode("latin-1", "replace")
        except (OSError, socket.error):
            pass
        return _fp("Redis", product, None)
    except (OSError, socket.error):
        return None
    finally:
        _close(sock)


def _try_memcached(host, port, timeout):
    sock = None
    try:
        sock = _connect(host, port, timeout)
        sock.settimeout(timeout)
        sock.sendall(b"version\r\n")
        data = _recv_some(sock)
    except (OSError, socket.error):
        return None
    finally:
        _close(sock)
    if data.upper().startswith(b"VERSION "):
        return _fp("Memcached", _decode(data), None)
    return None


def _try_rdp(host, port, timeout):
    sock = None
    probe = b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00"
    try:
        sock = _connect(host, port, timeout)
        sock.settimeout(timeout)
        sock.sendall(probe)
        data = _recv_some(sock)
    except (OSError, socket.error):
        return None
    finally:
        _close(sock)
    if data[:2] == b"\x03\x00":
        return _fp("RDP", "RDP", None)
    return None


def grab_banner(host, port, timeout=DEFAULT_BANNER_TIMEOUT):
    """Probe an open port and return a fingerprint dict, or ``None``."""
    if port in _REDIS_PORTS:
        fingerprint = _try_redis(host, port, timeout)
        if fingerprint:
            return fingerprint
    if port in _MEMCACHED_PORTS:
        fingerprint = _try_memcached(host, port, timeout)
        if fingerprint:
            return fingerprint
    if port in _RDP_PORTS:
        fingerprint = _try_rdp(host, port, timeout)
        if fingerprint:
            return fingerprint
    if port in _HTTP_PORTS:
        fingerprint = _try_http(host, port, timeout)
        if fingerprint:
            return fingerprint
    if port in _TLS_PORTS:
        fingerprint = _try_tls(host, port, timeout)
        if fingerprint:
            return fingerprint

    fingerprint = _try_passive(host, port, min(timeout, 0.35))
    if fingerprint and fingerprint.get("service"):
        return fingerprint
    # Ports already covered by the curated table rarely need generic HTTP/TLS
    # probing; unknown ports get the full fallback chain.
    if port in TCP_SERVICES:
        return None
    fingerprint = _try_http(host, port, timeout)
    if fingerprint:
        return fingerprint
    fingerprint = _try_tls(host, port, timeout)
    if fingerprint:
        return fingerprint
    return None


@lru_cache(maxsize=256)
def reverse_dns(host):
    """Return the PTR name for ``host`` or ``None``."""
    try:
        name, _, _ = socket.gethostbyaddr(host)
        return name
    except (socket.herror, socket.gaierror, OSError):
        return None


def is_local_target(host, local_ip=None):
    """Return True when ``host`` refers to this machine."""
    if not host:
        return False
    host = host.strip()
    if host in ("127.0.0.1", "::1", "localhost") or host.startswith("127."):
        return True
    local = set()
    if local_ip:
        local.add(local_ip)
    try:
        local.update(socket.gethostbyname_ex(socket.gethostname())[2])
    except (socket.gaierror, OSError):
        pass
    return host in local


@lru_cache(maxsize=1024)
def _windows_process_name(pid):
    if pid == 0:
        return "Idle"
    if pid == 4:
        return "System"
    try:
        import ctypes
        import ctypes.wintypes as wt

        kernel32 = ctypes.windll.kernel32
        kernel32.OpenProcess.restype = wt.HANDLE
        kernel32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
        kernel32.QueryFullProcessImageNameW.argtypes = [
            wt.HANDLE, wt.DWORD, wt.LPWSTR, ctypes.POINTER(wt.DWORD)
        ]
        kernel32.QueryFullProcessImageNameW.restype = wt.BOOL
        kernel32.CloseHandle.argtypes = [wt.HANDLE]
        kernel32.CloseHandle.restype = wt.BOOL
        handle = kernel32.OpenProcess(0x1000, False, pid)
        if not handle:
            return "PID %s" % pid
        try:
            buffer = ctypes.create_unicode_buffer(1024)
            size = wt.DWORD(1024)
            if kernel32.QueryFullProcessImageNameW(
                    handle, 0, buffer, ctypes.byref(size)):
                return os.path.basename(buffer.value) or ("PID %s" % pid)
        finally:
            kernel32.CloseHandle(handle)
    except Exception:
        pass
    return "PID %s" % pid


@lru_cache(maxsize=1)
def _windows_process_map_toolhelp():
    """Return ``{pid: image_name}`` using the Toolhelp32 snapshot API."""
    try:
        import ctypes
        import ctypes.wintypes as wt

        class PROCESSENTRY32W(ctypes.Structure):
            _fields_ = [
                ("dwSize", wt.DWORD),
                ("cntUsage", wt.DWORD),
                ("th32ProcessID", wt.DWORD),
                ("th32DefaultHeapID", ctypes.c_void_p),
                ("th32ModuleID", wt.DWORD),
                ("cntThreads", wt.DWORD),
                ("th32ParentProcessID", wt.DWORD),
                ("pcPriClassBase", ctypes.c_long),
                ("dwFlags", wt.DWORD),
                ("szExeFile", wt.WCHAR * 260),
            ]

        kernel32 = ctypes.windll.kernel32
        kernel32.CreateToolhelp32Snapshot.restype = wt.HANDLE
        kernel32.CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]
        kernel32.Process32FirstW.argtypes = [
            wt.HANDLE, ctypes.POINTER(PROCESSENTRY32W)
        ]
        kernel32.Process32FirstW.restype = wt.BOOL
        kernel32.Process32NextW.argtypes = [
            wt.HANDLE, ctypes.POINTER(PROCESSENTRY32W)
        ]
        kernel32.Process32NextW.restype = wt.BOOL
        kernel32.CloseHandle.argtypes = [wt.HANDLE]
        kernel32.CloseHandle.restype = wt.BOOL

        snapshot = kernel32.CreateToolhelp32Snapshot(0x00000002, 0)
        invalid = ctypes.c_void_p(-1).value
        if not snapshot or snapshot == invalid:
            return {}
        names = {}
        try:
            entry = PROCESSENTRY32W()
            entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
            if kernel32.Process32FirstW(snapshot, ctypes.byref(entry)):
                while True:
                    names[entry.th32ProcessID] = entry.szExeFile
                    if not kernel32.Process32NextW(
                            snapshot, ctypes.byref(entry)):
                        break
        finally:
            kernel32.CloseHandle(snapshot)
        return names
    except Exception:
        return {}


@lru_cache(maxsize=1)
def _windows_process_map():
    """Return ``{pid: image_name}`` from the OS process list."""
    names = _windows_process_map_toolhelp()
    if names:
        return names
    try:
        raw = subprocess.check_output(
            ["tasklist", "/FO", "CSV", "/NH"], stderr=subprocess.DEVNULL,
            timeout=10, creationflags=0x08000000,
        )
    except Exception:
        return {}
    reader = csv.reader(io.StringIO(raw.decode("latin-1", "replace")))
    for row in reader:
        if len(row) < 2:
            continue
        try:
            names[int(row[1])] = row[0]
        except (ValueError, IndexError):
            continue
    return names


def _windows_port_owners():
    try:
        raw = subprocess.check_output(
            ["netstat", "-ano"], stderr=subprocess.DEVNULL, timeout=10,
            creationflags=0x08000000,
        )
    except Exception:
        return {}
    process_names = _windows_process_map()
    owners = {}
    for line in raw.decode("latin-1", "replace").splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        proto = parts[0].lower()
        if proto not in ("tcp", "udp"):
            continue
        try:
            port = int(parts[1].rsplit(":", 1)[1])
        except (ValueError, IndexError):
            continue
        if not 0 < port <= 65535:
            continue
        if proto == "tcp":
            if len(parts) < 5:
                continue
            try:
                foreign_port = int(parts[2].rsplit(":", 1)[1])
            except (ValueError, IndexError):
                foreign_port = None
            if foreign_port not in (0, None):
                continue
        try:
            pid = int(parts[-1])
        except ValueError:
            continue
        owners[(proto, port)] = {
            "pid": pid,
            "process": process_names.get(pid) or _windows_process_name(pid),
        }
    return owners


def _linux_process_name(pid):
    try:
        with open("/proc/%s/comm" % pid) as handle:
            return handle.read().strip() or ("PID %s" % pid)
    except OSError:
        pass
    try:
        with open("/proc/%s/cmdline" % pid, "rb") as handle:
            data = handle.read().split(b"\x00")[0].decode("utf-8", "replace")
            return os.path.basename(data) or ("PID %s" % pid)
    except OSError:
        return "PID %s" % pid


def _linux_port_owners():
    inode_pid = {}
    try:
        pids = [name for name in os.listdir("/proc") if name.isdigit()]
    except OSError:
        return {}
    for name in pids:
        pid = int(name)
        fd_dir = "/proc/%s/fd" % name
        try:
            entries = os.listdir(fd_dir)
        except OSError:
            continue
        for entry in entries:
            try:
                target = os.readlink(os.path.join(fd_dir, entry))
            except OSError:
                continue
            if target.startswith("socket:["):
                inode_pid[target[8:-1]] = pid

    owners = {}
    sources = (
        ("tcp", "/proc/net/tcp"), ("tcp", "/proc/net/tcp6"),
        ("udp", "/proc/net/udp"), ("udp", "/proc/net/udp6"),
    )
    for proto, path in sources:
        try:
            with open(path) as handle:
                lines = handle.read().splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            parts = line.split()
            if len(parts) < 10:
                continue
            if proto == "tcp" and parts[3] != "0A":
                continue
            try:
                port = int(parts[1].rsplit(":", 1)[1], 16)
            except (ValueError, IndexError):
                continue
            pid = inode_pid.get(parts[9])
            if pid is None:
                continue
            owners[(proto, port)] = {
                "pid": pid,
                "process": _linux_process_name(pid),
            }
    return owners


def _macos_port_owners():
    owners = {}
    commands = (
        ("tcp", ["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"]),
        ("udp", ["lsof", "-nP", "-iUDP"]),
    )
    for proto, command in commands:
        try:
            raw = subprocess.check_output(
                command, stderr=subprocess.DEVNULL, timeout=10)
        except Exception:
            continue
        for line in raw.decode("latin-1", "replace").splitlines()[1:]:
            parts = line.split(None, 8)
            if len(parts) < 9:
                continue
            try:
                pid = int(parts[1])
            except ValueError:
                continue
            name_field = parts[8].replace("(LISTEN)", "").strip()
            endpoint = name_field.split()[-1] if name_field else ""
            try:
                port = int(endpoint.rsplit(":", 1)[1])
            except (ValueError, IndexError):
                continue
            owners[(proto, port)] = {
                "pid": pid,
                "process": os.path.basename(parts[0]),
            }
    return owners


def local_port_owners():
    """Return ``{(proto, port): {'pid': int, 'process': str}}`` for this host."""
    try:
        if os.name == "nt":
            return _windows_port_owners()
        if sys.platform == "darwin":
            return _macos_port_owners()
        return _linux_port_owners()
    except Exception:
        return {}


def attach_local_processes(results, host, local_ip=None):
    """Attach local process/PID info when scanning this machine."""
    if not results or not is_local_target(host, local_ip):
        return results
    owners = local_port_owners()
    if not owners:
        return results
    for result in results:
        proto = (result.get("proto") or "tcp").lower()
        owner = owners.get((proto, result.get("port")))
        if owner:
            result["pid"] = owner["pid"]
            result["process"] = owner["process"]
    return results
