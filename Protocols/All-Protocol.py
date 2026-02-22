# Import the socket module for network operations
import socket

# Define socket configuration for comprehensive port scanning
socket_family = socket.AF_INET  # IPv4 address family
socket_type = socket.SOCK_STREAM  # TCP protocol

# Get target IP address from user input
targetIp = input("Enter the hostname or IP address to scan: ")

# Get local machine hostname and resolve it to IP address
hostname = socket.gethostbyname(socket.gethostname())

# Print scanning information with source and target details
print(f"\nScanning {hostname} -> {targetIp} for open ports across all protocols... \n")

# Iterate through all available TCP ports (0-65535)
for port in range(65536):
    try:
        # Create a new socket with IPv4 and TCP configuration
        ns = socket.socket(socket_family, socket_type)
        # Set very low timeout for fast port enumeration (microseconds)
        ns.settimeout(0.000001)
        # Attempt to connect to the target IP and port using non-blocking method
        result = ns.connect_ex((targetIp, port))
        # Check if connection was successful (result == 0 indicates open port)
        if result == 0:
            print(f"Port {port} -> OPEN")
    except:
        # Close the socket if an exception occurs during connection attempt
        ns.close()