import nmap

n = nmap.PortScanner()

ipInput = '127.0.0.1'

ipScan = n.scan(ipInput)

hosts = n.all_hosts()

if not hosts:
  print("It Hosts Is Not Available !")
else:
  for host in hosts:
    print(f"host:{host}(hosts:{n[host].hostname() or "-----"})")
    print(f"Status: {n[host].state()}")
    print('--'*40)