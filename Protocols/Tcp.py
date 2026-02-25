# Import the socket module for network communication and operations
import socket

# Configure socket settings for TCP port scanning
socket_family = socket.AF_INET  # Use IPv4 addresses (AF_INET)
socket_type = socket.SOCK_STREAM  # Use TCP protocol (SOCK_STREAM)

# Prompt user to enter hostname or IP address to scan
targetIp = input("Enter the hostname or IP address to scan: ")

# Resolve hostname to IP address (if a hostname was provided)
info = socket.getaddrinfo(targetIp, None, socket_family, socket_type)

# Get the local machine's IP address
getHostName = socket.gethostbyname(socket.gethostname())

# Display banner with scanning source and destination information
print(f"\nScanning {getHostName} -> {targetIp} for open TCP ports... \n")

# Display source and target IP addresses
print(f"Hostname IP Address: {getHostName}\nTarget IP Address: {info[0][4][0]}\n")

# List of common TCP ports used by various network services and applications
TCP_Port = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445, 465, 514, 515, 587, 631, 636, 
    873, 990,993, 995, 1025, 1026, 1027, 1028, 1029, 1080, 1433, 1720, 1723, 1900, 2049, 2121, 3306, 3389,
    5432, 5900, 8080,8443, 7, 9, 13, 37, 88, 123, 179, 199, 427, 548, 554, 646, 992, 1521, 6379, 3000, 3001,
    5000, 5001, 5009, 5050,5060,5061, 8008, 8009, 8010, 8081, 8088, 8090, 8888, 9000, 9001, 9300, 11211, 27017,
    28017, 50000, 50070, 50075,50090,4444, 5555, 6666, 6667, 7777, 12345, 31337, 49152, 49153, 49154, 49155, 49156,
    49157
]

# Loop through each port (sorted from smallest to largest) and attempt connection
for port in sorted(TCP_Port):
    try:
        # Create a new socket with IPv4 and TCP configuration
        ns = socket.socket(socket_family, socket_type)
        # Set timeout to 1 microsecond (0.000001 seconds) for fast scanning
        ns.settimeout(0.000001)
        # Verify the connection result: 0 means successful connection (port is open)
        result = ns.connect_ex((targetIp, port))
        # Display port status only if it is open
        if result == 0:
            print(f"Port {port:>3} -> OPEN")
    finally:
        # Always close the socket to free up system resources
        ns.close()

# Announce completion of the scanning process
print("\nTCP port scanning completed.")