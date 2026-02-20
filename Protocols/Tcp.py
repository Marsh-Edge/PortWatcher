import socket

socket_family = socket.AF_INET
socket_type = socket.SOCK_STREAM

hostname = socket.gethostname()

gethostname = socket.gethostbyname(hostname)

for port in range(65535):
    try:
      ns = socket.socket(socket_family, socket_type)
      ns.settimeout(0.5)
      ns.bind((gethostname, port))
    except:
      print(f"Port {port} is in use.")
      ns.close()