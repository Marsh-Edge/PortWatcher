# Import the socket module for network operations
import socket

# Define socket configuration for TCP scanning
socket_family = socket.AF_INET  # IPv4 address family
socket_type = socket.SOCK_STREAM  # TCP protocol

# Get target IP address from user input
targetIp = input("Enter the hostname or IP address to scan: ")

# Get local machine hostname and resolve it to IP address
getHostName = socket.gethostbyname(socket.gethostname())

# Print scanning information with source and target details
print(f"\nScanning {getHostName} -> {targetIp} for open TCP ports... \n")

# List of common TCP ports to scan across different services
TCP_Port = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445, 465, 514, 515, 587, 631, 636, 873, 990, 993, 995,
    1025, 1026, 1027, 1028, 1029, 1080, 1433, 1720, 1723, 1900, 2049, 2121, 3306, 3389, 5432, 5900, 8080, 8443,
    7, 9, 13, 37, 88, 123, 179, 199, 427, 548, 554, 646, 873, 992, 1433, 1521, 3306, 5432, 6379, 27017, 9200,
    3000, 3001, 5000, 5001, 5009, 5050, 5060, 5061, 8008, 8009, 8010, 8081, 8088, 8090, 8443, 8888, 9000, 9001,
    9200, 9300, 11211, 27017, 28017, 50000, 50070, 50075, 50090,
    4444, 5555, 6666, 6667, 7777, 12345, 31337, 49152, 49153, 49154, 49155, 49156, 49157,
]

# Iterate through each port in the TCP port list
for port in TCP_Port:
    try:
        # Create a new socket with IPv4 and TCP configuration
        ns = socket.socket(socket_family, socket_type)
        # Set timeout to avoid hanging on unreachable ports (500ms)
        ns.settimeout(0.5)
        # Attempt to connect to the target IP and port
        result = ns.connect((targetIp, port))
        # Check the connection result and display port status
        if result != None:
            print(f"Port {port:>3} -> CLOSED")
        else:
            print(f"Port {port:>3} -> OPEN")
    except:
        # Close the socket if connection attempt fails or times out
        ns.close()