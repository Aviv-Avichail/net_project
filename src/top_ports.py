#!/usr/bin/env python3
import sys
import os
import matplotlib.pyplot as plt
import numpy as np
from collections import Counter
from scapy.all import rdpcap, TCP, UDP

MAX_PORTS_TO_DISPLAY = 20

def analyze_pcap(pcap_file):
    """
    Reads the pcap file and extracts destination ports from TCP and UDP packets.
    Returns a list of destination ports.
    """
    if not os.path.isfile(pcap_file):
        print(f"Error: File '{pcap_file}' does not exist.")
        sys.exit(1)

    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"Error reading pcap file '{pcap_file}': {e}")
        sys.exit(1)

    destination_ports = []
    for packet in packets:
        if TCP in packet:
            destination_ports.append(packet[TCP].dport)
        elif UDP in packet:
            destination_ports.append(packet[UDP].dport)

    return destination_ports

def plot_top_ports(destination_ports, pcap_filename):
    """
    Plots the top N (MAX_PORTS_TO_DISPLAY) destination ports using a bar chart
    and saves the figure as a PNG file in the same folder as this script.
    """
    if not destination_ports:
        print("No TCP or UDP destination ports found in the pcap file.")
        return

    port_counter = Counter(destination_ports)
    top_ports = port_counter.most_common(MAX_PORTS_TO_DISPLAY)
    if not top_ports:
        print("No destination ports to plot.")
        return

    ports, counts = zip(*top_ports)
    x_positions = np.arange(len(ports))

    plt.figure(figsize=(10, 6))
    # Use skyblue color for these bars
    plt.bar(x_positions, counts, color='skyblue', edgecolor='black')
    plt.xlabel("Destination Port")
    plt.ylabel("Number of Packets")
    plt.title(f"Top {MAX_PORTS_TO_DISPLAY} Destination Ports")
    plt.xticks(x_positions, ports, rotation=45)
    plt.tight_layout()

    script_dir = os.path.dirname(os.path.abspath(__file__))
    output_file = os.path.join(script_dir, f"top_{MAX_PORTS_TO_DISPLAY}_dest_ports_{pcap_filename}.png")
    plt.savefig(output_file)
    plt.show()
    print(f"Port distribution plot saved as: {output_file}")

def main():
    """
    Usage: python top_ports.py <pcap_file>
    """
    if len(sys.argv) != 2:
        print("Usage: python top_ports.py <pcap_file>")
        sys.exit(1)

    pcap_file = sys.argv[1]
    destination_ports = analyze_pcap(pcap_file)
    plot_top_ports(destination_ports, os.path.basename(pcap_file))

if __name__ == "__main__":
    main()
