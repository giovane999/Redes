#! /usr/bin/python3


import sys
from datetime import datetime 
from scapy.all import * 

try: 
    interface = input("\n[*] Set interface: ")
    ips = input("[*] Set IP RANGE ou Network: ")
except KeyboardInterrupt:
    print("\n User Aborted!")
    sys.exit()

print("Scaniando...")
start_time = datetime.now()
conf.verb = 0 

ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst = ips), timeout = 2, iface=interface, inter=0.1)

print("\n\tMAC\t\tIP\n")

for snd,rcv in ans:
    print(rcv.sprintf("%Ether.src% - %ARP.psrc%"))
stop_time = datetime.now()
total_time = stop_time - start_time
print("\n[*] Scan Completo!")
print("[*] Duracao do Scan %s" %(total_time))