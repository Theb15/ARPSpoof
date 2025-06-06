from scapy.all import ARP, sniff

# Dictionary to keep track of IP-to-MAC associations
ip_mac_map = {}

def arp_monitor_callback(packet):
    if packet.haslayer(ARP):
        arp_layer = packet[ARP]
        ip = arp_layer.psrc  # Source IP from ARP
        mac = arp_layer.hwsrc  # Source MAC from ARP

        # Check if this IP has been seen with a different MAC
        if ip in ip_mac_map:
            if ip_mac_map[ip] != mac:
                print(f"[ALERT] Possible ARP Spoofing detected for IP {ip}!")
                print(f"Previous MAC: {ip_mac_map[ip]} - New MAC: {mac}")
        else:
            ip_mac_map[ip] = mac
            print(f"Observed ARP: IP {ip} is associated with MAC {mac}")

print("Starting live ARP spoofing detection. Press Ctrl+C to stop...")
sniff(filter="arp", prn=arp_monitor_callback, store=0)
