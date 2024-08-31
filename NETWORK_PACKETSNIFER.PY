from scapy.all import sniff

# Function to handle each captured packet
def packet_handler(packet):
    # Display packet summary
    print(packet.summary())

    # Check if the packet has an IP layer
    if packet.haslayer('IP'):
        ip_layer = packet['IP']
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")
        print(f"Protocol: {ip_layer.proto}")

    # Check if the packet has a TCP layer
    if packet.haslayer('TCP'):
        tcp_layer = packet['TCP']
        print(f"Source Port: {tcp_layer.sport}")
        print(f"Destination Port: {tcp_layer.dport}")
        print("Payload:", packet[TCP].payload)

    # Check if the packet has a UDP layer
    if packet.haslayer('UDP'):
        udp_layer = packet['UDP']
        print(f"Source Port: {udp_layer.sport}")
        print(f"Destination Port: {udp_layer.dport}")
        print("Payload:", packet[UDP].payload)

    print("-" * 50)

# Main function to start sniffing packets
def start_sniffing():
    print("Starting packet capture...")
    sniff(prn=packet_handler, count=10)  # Capture 10 packets (or use count=0 for unlimited capture)

if __name__ == "__main__":
    start_sniffing()