from scapy.all import *
import argparse

def start_sniffer(interface=None):
    # Define the packet callback function within the sniffer
    def packet_callback(packet):
        try:
            print("-" * 60)
            if packet.haslayer(TCP):
                print(f"[TCP] {packet.summary()}")
                print(f"       Src Port: {packet[TCP].sport} -> Dst Port {packet[TCP].dport}")
            elif  packet.haslayer(UDP):
                print(f"[UDP] {packet.summary()}")
                print(f"       Src Port: {packet[UDP].sport} -> Dst Port {packet[UDP].dport}")

            elif packet.haslayer(ICMP):
                print(f"[ICMP] {packet.summary()}")
                print(f"       Src IP: {packet[IP].src} -> Dst IP {packet[IP].dst}")

            elif packet.haslayer(ARP):
                print(f"[ARP] {packet.summary()}")
                print(f"       Src MAC: {packet[ARP].hwsrc} -> Dst MAC {packet[ARP].hwdst}")

            elif packet.haslayer(DNS):
                print(f"[DNS] {packet.summary()}")

                if packet[DNS].qd:
                    print(f"     Query: {packet[DNS].qd.qname.decode()}")
                if packet[DNS].an:
                    print(f"     Answer: {packet[DNS].an.rdata}")
        
            elif packet.haslayer(Raw):
                payload = packet[Raw].load
                if b'HTTP' in payload:
                    print(f"[HTTP] {packet.summary()}")
                    print(f"     Data: {payload.decode(errors='ignore')}")

                else:
                    print(f"[Raw Data]: {payload.decode(errors='ignore')}")
                
        except Exception as e:
            print(f"Error processing packet: {e}")

    # Start sniffing on the specified interface
    print(f"Starting sniffer on {interface}")
    sniff(iface=interface, prn=packet_callback)
    
    

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Network sniffer")
    parser.add_argument('-i','--interface', type=str, help="Network interface to use")
    args = parser.parse_args()


    start_sniffer(interface=args.interface)


            

       
            
