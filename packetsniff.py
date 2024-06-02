import threading
from scapy.all import sniff, get_if_list, IP, TCP, UDP, ICMP, Raw

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
        else:
            print("Invalid interface number.")
    except ValueError:
        print("Invalid input. Please enter a number.")

def process_packet(packet):
    if packet.haslayer(IP):
        ip_layer = packet.getlayer(IP)
        print(f"\n[+] New Packet: {ip_layer.src} -> {ip_layer.dst}")

        if packet.haslayer(TCP):
            tcp_layer = packet.getlayer(TCP)
            print(f"   [TCP] {tcp_layer.sport} -> {tcp_layer.dport}")
            print(f"   [Flags] SYN: {tcp_layer.flags & 0x02}, ACK: {tcp_layer.flags & 0x10}, PSH: {tcp_layer.flags & 0x08}, RST: {tcp_layer.flags & 0x04}, FIN: {tcp_layer.flags & 0x01}")

        elif packet.haslayer(UDP):
            udp_layer = packet.getlayer(UDP)
            print(f"   [UDP] {udp_layer.sport} -> {udp_layer.dport}")

        elif packet.haslayer(ICMP):
            icmp_layer = packet.getlayer(ICMP)
            print(f"   [ICMP] Type: {icmp_layer.type}, Code: {icmp_layer.code}")

        print(f"   [Raw] {bytes(packet[IP]).hex()}")

def start_sniffing(interface):
    print(f"Sniffing on interface: {interface}")
    sniff_thread = threading.Thread(target=sniff_packets, args=(interface,))
    sniff_thread.daemon = True
    sniff_thread.start()
    sniff_thread.join()

def sniff_packets(interface):
    sniff(iface=interface, prn=process_packet, store=False)

if __name__ == "__main__":
    main()
