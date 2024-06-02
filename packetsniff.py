import threading
from scapy.all import sniff, get_if_list, IP, TCP, UDP, ICMP, Raw, DNS
from datetime import datetime
import zlib

packet_counts = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'HTTP': 0, 'DNS': 0}

def main():
    print("Available interfaces:")
    interfaces = get_if_list()
    for i, interface in enumerate(interfaces, start=1):
        print(f"{i}. {interface}")

    choice = input("Select interface by entering its number: ")
    try:
        interface_index = int(choice) - 1
        if 0 <= interface_index < len(interfaces):
            interface = interfaces[interface_index]
            start_sniffing(interface)
            # Keep the main thread alive until the user decides to exit
            while True:
                pass
        else:
            print("Invalid interface number.")
    except ValueError:
        print("Invalid input. Please enter a number.")

def process_packet(packet):
    global packet_counts

    if packet.haslayer(IP):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"\n{timestamp}")
        
        # Flag packets by IP layer protocol type
        ip_layer = packet.getlayer(IP)
        protocol = "Unknown"
        if ip_layer.proto == 1:
            protocol = "ICMP"
        elif ip_layer.proto == 6:
            protocol = "TCP"
        elif ip_layer.proto == 17:
            protocol = "UDP"
        elif ip_layer.proto == 47:
            protocol = "GRE"
        elif ip_layer.proto == 50:
            protocol = "ESP"
        elif ip_layer.proto == 51:
            protocol = "AH"
        elif ip_layer.proto == 89:
            protocol = "OSPF"
        elif ip_layer.proto == 132:
            protocol = "SCTP"
        else:
            protocol = f"Unknown ({ip_layer.proto})"

        print(f" [+] New Packet: {ip_layer.src} -> {ip_layer.dst}, Protocol: {protocol}, Length: {len(packet)}")
        packet_counts[protocol] += 1

        # Handle specific protocol types
        if packet.haslayer(TCP):
            tcp_layer = packet.getlayer(TCP)
            flags = []
            if tcp_layer.flags & 0x01:
                flags.append("FIN")
            if tcp_layer.flags & 0x02:
                flags.append("SYN")
            if tcp_layer.flags & 0x04:
                flags.append("RST")
            if tcp_layer.flags & 0x08:
                flags.append("PSH")
            if tcp_layer.flags & 0x10:
                flags.append("ACK")
            if tcp_layer.flags & 0x20:
                flags.append("URG")
            print(f"   [TCP] {tcp_layer.sport} -> {tcp_layer.dport}, Flags: {', '.join(flags)}")

            # Check if the packet has a Raw layer
            raw_layer = packet.getlayer(Raw)
            if raw_layer:
                raw_data = raw_layer.load
                if b'HTTP' in raw_data:
                    packet_counts['HTTP'] += 1
                    http_payload = raw_data

                    # Check if the response is gzip compressed
                    if b'Content-Encoding: gzip' in raw_data:
                        try:
                            http_payload = zlib.decompress(http_payload, 16+zlib.MAX_WBITS)
                        except zlib.error:
                            print("[Gzip Decompression Error]")
                            return

                    try:
                        http_payload = http_payload.decode('utf-8')
                    except UnicodeDecodeError:
                        http_payload = http_payload.decode('latin-1')

                    print(f"   [HTTP Payload]:\n{http_payload}")

        elif packet.haslayer(UDP):
            udp_layer = packet.getlayer(UDP)
            print(f"   [UDP] {udp_layer.sport} -> {udp_layer.dport}")

            if udp_layer.dport == 53 or udp_layer.sport == 53:
                packet_counts['DNS'] += 1
                dns_payload = packet.getlayer(DNS).summary()
                print(f"   [DNS Query]:\n{dns_payload}")

        elif packet.haslayer(ICMP):
            icmp_layer = packet.getlayer(ICMP)
            print(f"   [ICMP] Type: {icmp_layer.type}, Code: {icmp_layer.code}")

def start_sniffing(interface):
    print(f"\nSniffing on interface: {interface}")
    sniff_thread = threading.Thread(target=sniff_packets, args=(interface,))
    sniff_thread.daemon = True
    sniff_thread.start()

def sniff_packets(interface):
    sniff(iface=interface, prn=process_packet, store=False)

if __name__ == "__main__":
    main()
