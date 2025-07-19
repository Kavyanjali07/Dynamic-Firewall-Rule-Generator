from scapy.all import sniff, IP

def monitor(packet):
    if packet.haslayer(IP):
        ip = packet[IP]
        print(f"Captured packet: {ip.src} → {ip.dst} | Len: {len(packet)}")

print("📡 Sniffing on lo...")
sniff(iface="lo", prn=monitor, store=False)
