import sys
import os
import matplotlib.pyplot as plt
from scapy.all import rdpcap, IP, IPv6
from collections import Counter

TOP_N_ADDRESSES = 5

def plot_top5_destinations(pcap_file_path):
    """
    Reads a pcap/pcapng file, extracts both IPv4 and IPv6 destination addresses,
    and displays a bar chart of the top N (TOP_N_ADDRESSES) most frequent destinations.
    """
    if not os.path.isfile(pcap_file_path):
        print(f"Error: File '{pcap_file_path}' does not exist.")
        return

    try:
        packets = rdpcap(pcap_file_path)
    except Exception as e:
        print(f"Error reading pcap file '{pcap_file_path}': {e}")
        return

    destination_addresses = []
    for packet in packets:
        if IP in packet:
            destination_addresses.append(packet[IP].dst)
        elif IPv6 in packet:
            destination_addresses.append(packet[IPv6].dst)

    if not destination_addresses:
        print("No IPv4 or IPv6 packets found in the file.")
        return

    address_counter = Counter(destination_addresses)
    top_addresses = address_counter.most_common(TOP_N_ADDRESSES)
    if not top_addresses:
        print("No addresses to plot.")
        return

    addresses, frequencies = zip(*top_addresses)

    plt.figure(figsize=(10, 6))
    # Default color for bars is 'C0' (blue)
    plt.bar(addresses, frequencies, edgecolor='black')
    plt.title(f"Top {TOP_N_ADDRESSES} Destination IP Addresses")
    plt.xlabel("Destination IP Address")
    plt.ylabel("Frequency")
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    plt.show()

def main():
    """
    Usage: python top5_ip.py <pcap_file>
    """
    if len(sys.argv) != 2:
        print("Usage: python top5_ip.py <pcap_file>")
        sys.exit(1)

    pcap_file = sys.argv[1]
    plot_top5_destinations(pcap_file)

if __name__ == "__main__":
    main()
