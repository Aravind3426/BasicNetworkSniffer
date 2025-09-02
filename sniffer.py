from scapy.all import sniff, IP, TCP, UDP

def packet_handler(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        
        if proto == 6:
            protocol = "TCP"
        elif proto == 17:
            protocol = "UDP"
        else:
            protocol = str(proto)

        print(f"[+] {protocol} Packet: {src_ip} -> {dst_ip}")

        if packet.haslayer(TCP) or packet.haslayer(UDP):
            payload = bytes(packet[TCP].payload) if packet.haslayer(TCP) else bytes(packet[UDP].payload)
            if payload:
                print(f"    Payload: {payload[:50]}")  

print("Starting packet capture... Press Ctrl+C to stop.")
sniff(filter="tcp port 80",prn=packet_handler, store=0)
