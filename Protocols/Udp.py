import socket


connectionFamily = socket.AF_INET
connectionType = socket.SOCK_STREAM


connection = socket.socket(connectionFamily, connectionType)

targetIp = input("Enter the hostname or IP address to scan: ")

udpList = {
    "HTTPS":[80],
    "DNS": [53],
    "DHCP": [67, 68],
    "TFTP": [69],
    "NTP": [123],
    "SNMP": [161, 162],
    "Syslog": [514],
    "RIP": [520],
    "IPsec/IKE": [500, 4500],
    "mDNS": [5353],
    "SIP": [5060],
    "RADIUS": [1812, 1813],
    "Kerberos": [88],
    "NetBIOS": [137, 138],
    "QUIC/HTTP3": [443],
    "OpenVPN": [1194],
    "WireGuard": [51820],
}


def createConnection():
    openPortsList = []
    # try:
    for protocol , port in udpList.items():
            result = connection.connect((targetIp, port[0]))
            openPortsList.append(port[0])
            
    # except KeyboardInterrupt:
    #     print('Exiting')
    #     return
    


createConnection()
