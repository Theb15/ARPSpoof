from scapy.all import ARP, rdpcap
import subprocess
import platform
pcap_file = r"C:\Users\baala\Documents\DA_2CCNPacket.pcapng"
packets = rdpcap(pcap_file)
ip_mac_map = {}

def block_spoofed_ip(suspect_ip):
    """
    FIREWALL IMPLEMENTATION (Windows):
    This function adds a Windows Firewall rule to block traffic from the suspicious IP address.
    Windows Firewall does not support blocking by MAC address, so we block by IP instead.
    """
    cmd = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        "name=BlockSpoofedIP",
        "dir=in",              
        "action=block",
        f"remoteip={suspect_ip}"
    ]
    try:
        subprocess.run(cmd, check=True, shell=True)
        print(f"[INFO] Firewall rule added to block IP {suspect_ip}")
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Failed to add firewall rule: {e}")

for packet in packets:
    if packet.haslayer(ARP):
        arp_layer = packet[ARP]
        ip = arp_layer.psrc
        mac = arp_layer.hwsrc
        if ip in ip_mac_map:
            if ip_mac_map[ip] != mac:
                print(f"[ALERT] Possible ARP Spoofing detected for IP {ip}!")
                print(f"Previous MAC: {ip_mac_map[ip]} - New MAC: {mac}")
                block_spoofed_ip(ip)
        else:
            ip_mac_map[ip] = mac
            print(f"Observed ARP: IP {ip} is associated with MAC {mac}")