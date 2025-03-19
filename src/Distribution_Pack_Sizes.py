import sys
import os
import matplotlib.pyplot as plt
from scapy.all import rdpcap

DEFAULT_BINS = 50

def plot_packet_size_distribution(pcap_path):
    """
    Reads a pcap/pcapng file from the given path, extracts packet sizes,
    and plots a histogram of their distribution.
    """
    if not os.path.isfile(pcap_path):
        print(f"Error: File '{pcap_path}' does not exist.")
        return

    try:
        packets = rdpcap(pcap_path)
    except Exception as e:
        print(f"Error reading pcap file '{pcap_path}': {e}")
        return

    if len(packets) == 0:
        print("No packets found in the pcap file.")
        return

    packet_sizes = [len(pkt) for pkt in packets]

    plt.figure(figsize=(10, 6))
    plt.hist(packet_sizes, bins=DEFAULT_BINS, edgecolor='black')
    plt.xlabel("Packet Size (bytes)")
    plt.ylabel("Number of Packets")
    plt.title("Distribution of Packet Sizes")
    plt.grid(True)  # Show grid lines
    plt.tight_layout()
    plt.show()

def main():
    """
    Usage: python Distribution_Pack_Sizes.py <pcap_file>
    """
    if len(sys.argv) != 2:
        print("Usage: python Distribution_Pack_Sizes.py <pcap_file>")
        sys.exit(1)

    pcap_file = sys.argv[1]
    plot_packet_size_distribution(pcap_file)

if __name__ == "__main__":
    main()
