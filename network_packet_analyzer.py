from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP

# ------------------------------------------------------------
# NETWORK PACKET ANALYZER
# Developed using Python and Scapy
# ------------------------------------------------------------

packet_count = 0


def display_heading():
    print("=" * 70)
    print("NETWORK PACKET ANALYZER")
    print("=" * 70)
    print("Capturing live network packets...")
    print("Press Ctrl + C to stop at any time.")
    print("=" * 70)


def identify_protocol(packet):
    if packet.haslayer(TCP):
        return "TCP"
    elif packet.haslayer(UDP):
        return "UDP"
    elif packet.haslayer(ICMP):
        return "ICMP"
    else:
        return "OTHER"


def packet_details(packet):
    global packet_count
    packet_count += 1

    print("\n")
    print("=" * 70)
    print("Packet Number :", packet_count)

    if packet.haslayer(IP):
        ip = packet[IP]

        print("Source IP       :", ip.src)
        print("Destination IP  :", ip.dst)
        print("Protocol        :", identify_protocol(packet))
        print("Packet Length   :", len(packet), "Bytes")
        print("Packet Summary  :", packet.summary())

        if packet.haslayer(TCP):
            print("Source Port     :", packet[TCP].sport)
            print("Destination Port:", packet[TCP].dport)

        elif packet.haslayer(UDP):
            print("Source Port     :", packet[UDP].sport)
            print("Destination Port:", packet[UDP].dport)

        elif packet.haslayer(ICMP):
            print("ICMP Packet Detected")

    else:
        print("Non-IP Packet Captured")
        print(packet.summary())

    print("=" * 70)


def start_capture():
    print("\nStarting Packet Capture...\n")
    sniff(prn=packet_details, count=20, store=False)

    print("\n")
    print("=" * 70)
    print("Packet Capture Completed")
    print("Total Packets Captured :", packet_count)
    print("=" * 70)


# ---------------- Main Program ----------------

display_heading()
start_capture()
