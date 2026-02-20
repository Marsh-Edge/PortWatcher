# This is test code for getting understand of socket library
# this section we import library's
import socket

# this section we create the type of connection we want
socket_family = socket.AF_INET
socket_type = socket.SOCK_DGRAM
# this section we create a socket connection with ipv4 and udp protocol
# called conection 
connection = socket.socket(socket_family,socket_type)
# in this section we get host name
host_name = socket.gethostname()

# in this section we get ip address of host by his nane
host_address = socket.gethostbyname(host_name)

print(host_address)

for port in range(65535):

    try:

        connection.bind((host_address, 49690))
    except:
        print(f'true connection ,{port}')

connection.close()
