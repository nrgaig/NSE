import scapy
from scapy.all import *
balance = 0
ip_list={}

def duplicate_arp_packets(packet): # detects duplicate MAC address for different IPs
    src_ip = ""
    src_mac = ""
    if ARP in packet:
        if packet[ARP].op == 2:
            src_mac = packet[ARP].hwsrc
            src_ip = packet[ARP].psrc
        if src_ip in ip_list:
            if ip_list[src_ip] != src_mac:
                print("WARNING: Duplicate arp detected")
        else:
            ip_list[src_ip] = src_mac

def free_arp_packets(packet): # detects IS-AT packets which were not asked for
    global balance
    if ARP in packet:
        if packet[ARP].op == 1:
            balance += 1
        elif packet[ARP].op == 2:
            balance -= 1

        if balance < -3:
            print("WARNING: Free ARP packets detected")



def arp_filter(packet): # call for the detection methods
    if ARP in packet:
        duplicate_arp_packets(packet)
        free_arp_packets(packet)



sniff(filter="arp", prn=arp_filter) # sniffing packets and sending to arp_filter

