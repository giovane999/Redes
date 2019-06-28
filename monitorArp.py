#! /usr/bin/python3

from scapy.all import * 

def arp_display(pkt):
    if pkt[ARP].op == 1:
        return "\n[*] Requisição: " + pkt[ARP].psrc + " esta perguntando por " + pkt[ARP].pdst
        
    if pkt[ARP].op == 2:
        return "Resposta: " + pkt[ARP].hwsrc + "tem o endereço " + pkt[ARP].psrc

print(sniff(prn=arp_display, filter="arp", store=0)) 
