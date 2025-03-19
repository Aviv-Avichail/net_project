#!/usr/bin/env python3
import sys
import os
import matplotlib.pyplot as plt
from collections import Counter
from scapy.all import rdpcap, TCP, UDP
import numpy as np


def analyze_pcap(pcap_file):
    """
    Reads the pcap file and extracts destination ports from TCP and UDP packets.
    """
    try:
        packets = rdpcap(pcap_file)
    except FileNotFoundError:
        print("Error: File not found:", pcap_file)
        sys.exit(1)
    except Exception as e:
        print("Error reading pcap file:", e)
        sys.exit(1)

    dest_ports = []
    for pkt in packets:
        # Check for TCP destination port
        if TCP in pkt:
            dest_ports.append(pkt[TCP].dport)
        # Check for UDP destination port
        elif UDP in pkt:
            dest_ports.append(pkt[UDP].dport)

    return dest_ports


def plot_top_ports(dest_ports,pcap_file):
    """
    Plots the top 20 destination ports using a bar chart and saves the figure
    as a PNG file in the same folder as this script.
    """
    port_counts = Counter(dest_ports)
    top_20 = port_counts.most_common(20)

    if not top_20:
        print("No TCP or UDP destination ports found in the pcap file.")
        sys.exit(1)

    ports, counts = zip(*top_20)
    x_positions = np.arange(len(ports))

    plt.figure(figsize=(10, 6))
    plt.bar(x_positions, counts, color='skyblue')
    plt.xlabel("Destination Port")
    plt.ylabel("Number of Packets")
    plt.title("Top 20 Destination Ports")
    plt.xticks(x_positions, ports, rotation=45)
    plt.tight_layout()

    # Save the figure in the same directory as this script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    output_file = os.path.join(script_dir, f"top_20_dest_ports_{pcap_file}.png")
    plt.savefig(output_file)
    plt.show()


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 top_ports.py <pcap_file>")
        sys.exit(1)

    pcap_file = sys.argv[1]
    dest_ports = analyze_pcap(pcap_file)
    plot_top_ports(dest_ports,pcap_file)


if __name__ == "__main__":
    main()
