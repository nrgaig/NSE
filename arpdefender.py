import scapy
from scapy.all import *
balance = 0
ip_list={}

def duplicate_arp_packets(packet):
    src_ip = ""
    src_mac = ""
    if ARP in packet:
        if packet[ARP].op == 2:
            src_mac = packet[ARP].hwsrc
            src_ip = packet[ARP].psrc
        if src_ip in ip_list:
            if ip_list[src_ip] != src_mac:
                print("Duplicate arp detected")
        else:
            ip_list[src_ip] = src_mac

def free_arp_packets(packet):
    global balance
    if ARP in packet:
        if packet[ARP].op == 1:
            balance += 1
        elif packet[ARP].op == 2:
            balance -= 1

        if balance < -3:
            print("Arp spoofing detected")



def arp_filter(packet):
    if ARP in packet:

        duplicate_arp_packets(packet)
        free_arp_packets(packet)



sniff(filter="arp", prn=arp_filter)

