# Import the socket module for network communication and operations
import socket

# Configure socket settings for comprehensive port scanning
socket_family = socket.AF_INET  # Use IPv4 addresses (AF_INET)
socket_type = socket.SOCK_STREAM  # Use TCP protocol (SOCK_STREAM)

# Prompt user to enter hostname or IP address to scan
targetIp = input("Enter the hostname or IP address to scan: ")

# Resolve hostname to IP address (if a hostname was provided)
info = socket.getaddrinfo(targetIp, None, socket_family, socket_type)

# Get the local machine's IP address
hostname = socket.gethostbyname(socket.gethostname())

# Display banner with scanning source and destination information
print(f"\nScanning {hostname} -> {targetIp} for open ports across all protocols... \n")

# Display source and target IP addresses
print(f"Hostname IP Address: {hostname}\nTarget IP Address: {info[0][4][0]}\n")

# Loop through all available TCP ports (0-65535) and attempt connection to each
for port in range(65536):
    try:
        # Create a new socket with IPv4 and TCP configuration
        ns = socket.socket(socket_family, socket_type)
        # Set timeout to 1 microsecond (0.000001 seconds) for fast scanning
        ns.settimeout(0.000001)
        # Verify the connection result: 0 means successful connection (port is open)
        result = ns.connect_ex((targetIp, port))
        # Display port status only if it is open
        if result == 0:
            print(f"Port {port:>5} -> OPEN")
    finally:
        # Always close the socket to free up system resources
        ns.close()

# Announce completion of the comprehensive port scanning process
print("\nComprehensive port scanning completed.")