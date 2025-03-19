#!/usr/bin/env python3
import sys
import os
import matplotlib.pyplot as plt
from scapy.all import rdpcap, IP, IPv6, TCP, UDP

MIN_EPHEMERAL_PORT = 1024

def classify_packet(packet):
    """
    Classifies a packet as 'upstream' or 'downstream' based on port numbers.
    - 'upstream' if source port >= 1024 and destination port < 1024 (client to server)
    - 'downstream' if source port < 1024 and destination port >= 1024 (server to client)
    Returns:
        "upstream", "downstream", or None if it cannot be classified.
    """
    # Check for IP layer (IPv4 or IPv6)
    if not (IP in packet or IPv6 in packet):
        return None

    # Look for TCP or UDP layer
    if TCP in packet:
        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport
    elif UDP in packet:
        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport
    else:
        return None

    # Apply the heuristic
    if source_port >= MIN_EPHEMERAL_PORT and destination_port < MIN_EPHEMERAL_PORT:
        return "upstream"
    elif source_port < MIN_EPHEMERAL_PORT and destination_port >= MIN_EPHEMERAL_PORT:
        return "downstream"
    else:
        return None

def analyze_pcap(pcap_file):
    """
    Reads the pcap file and sums the total bytes for upstream and downstream packets
    that can be classified using the heuristic.
    Returns:
        (total_upstream_bytes, total_downstream_bytes)
    """
    if not os.path.isfile(pcap_file):
        print(f"Error: File '{pcap_file}' does not exist.")
        sys.exit(1)

    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"Error reading pcap file '{pcap_file}': {e}")
        sys.exit(1)

    total_upstream_bytes = 0
    total_downstream_bytes = 0

    for packet in packets:
        direction = classify_packet(packet)
        if direction == "upstream":
            total_upstream_bytes += len(packet)
        elif direction == "downstream":
            total_downstream_bytes += len(packet)

    return total_upstream_bytes, total_downstream_bytes

def plot_up_vs_down(upstream_bytes, downstream_bytes):
    """
    Plots a bar chart comparing the total upstream vs downstream bytes.
    The upstream bar is colored in muted green ("lightgreen") and the downstream bar in muted red ("salmon").
    Saves the plot as 'upstream_vs_downstream.png' in the same folder as the script.
    """
    categories = ['Upstream', 'Downstream']
    amounts = [upstream_bytes, downstream_bytes]

    plt.figure(figsize=(6, 6))
    # Use muted colors for upstream and downstream
    bars = plt.bar(categories, amounts, color=['lightgreen', 'salmon'], edgecolor='black')
    plt.ylabel("Total Bytes")
    plt.title("Upstream vs Downstream Traffic")

    # Annotate each bar with the exact value
    for bar in bars:
        height = bar.get_height()
        plt.annotate(f'{height:,}',
                     xy=(bar.get_x() + bar.get_width() / 2, height),
                     xytext=(0, 3),
                     textcoords="offset points",
                     ha='center', va='bottom')

    plt.tight_layout()

    script_dir = os.path.dirname(os.path.abspath(__file__))
    output_file = os.path.join(script_dir, "upstream_vs_downstream.png")
    plt.savefig(output_file)
    plt.show()
    print("Plot saved as:", output_file)

def main():
    """
    Usage: python upstream_downstream.py <pcap_file>
    """
    if len(sys.argv) != 2:
        print("Usage: python upstream_downstream.py <pcap_file>")
        sys.exit(1)

    pcap_file = sys.argv[1]
    upstream, downstream = analyze_pcap(pcap_file)
    print(f"Total Upstream Bytes: {upstream:,}")
    print(f"Total Downstream Bytes: {downstream:,}")
    plot_up_vs_down(upstream, downstream)

if __name__ == "__main__":
    main()
