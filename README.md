# CodeAlpha_BasicNetworkSniffer
task1

from scapy.all import sniff, IP, TCP, UDP

# Function to process captured packets
def packet_callback(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "Other"

        print(f"Source IP: {src_ip} -> Destination IP: {dst_ip}, Protocol: {protocol}")

        # Display payload if available
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            payload = bytes(packet[TCP].payload) if packet.haslayer(TCP) else bytes(packet[UDP].payload)
            if payload:
                print(f"Payload Data: {payload[:50]}...")  # Display first 50 bytes of payload
            
        print("-" * 50)

# Capture packets on the network
print("Starting packet capture... Press Ctrl+C to stop.")
sniff(prn=packet_callback, count=20)  # Captures 20 packets
