from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP


output_file = "analyzer.txt"

def get_protocol_name(protocol_number):
    """Return the protocol name given the protocol number."""
    protocol_map = {
        6: "TCP",
        17: "UDP",
        1: "ICMP"
    }
    return protocol_map.get(protocol_number, "Unknown")

def packet_callback(packet):
    """Callback function to process each packet."""
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        protocol_name = get_protocol_name(protocol)
        payload = packet[IP].payload
        
        packet_info = (
            f"Source IP: {ip_src}\n"
            f"Destination IP: {ip_dst}\n"
            f"Protocol: {protocol_name}\n"
            f"Payload: {payload}\n"
            + "-" * 50 + "\n"
        )
        
        # Print packet information to the console
        print(packet_info)
        
        # Write packet information to the file
        with open(output_file, "a") as f:
            f.write(packet_info)

def main():
    """Main function to start packet sniffing."""
    # Start sniffing packets
    sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    main()
