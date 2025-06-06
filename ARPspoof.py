from scapy.all import ARP, sniff
import time
from scapy.all import rdpcap, ARP

# Specify your .pcapng file name (adjust the file name/path if necessary)
pcap_file = "C:\\Users\\baala\\Documents\\DA_2CCNPacket.pcapng"

# Read all packets from the .pcapng file
packets = rdpcap(pcap_file)

# Dictionary to keep track of seen IP-to-MAC associations
ip_mac_map = {}

# Process each packet in the capture
for packet in packets:
    if packet.haslayer(ARP):
        arp_layer = packet[ARP]
        ip = arp_layer.psrc  # Source IP from ARP
        mac = arp_layer.hwsrc  # Source MAC from ARP

        # If IP already seen with a different MAC, flag as potential spoofing
        if ip in ip_mac_map:
            if ip_mac_map[ip] != mac:
                print(f"[ALERT] Possible ARP Spoofing detected for IP {ip}!")
                print(f"Previous MAC: {ip_mac_map[ip]} - New MAC: {mac}")
        else:
            ip_mac_map[ip] = mac
            print(f"Observed ARP: IP {ip} is associated with MAC {mac}")
