#!/usr/bin/env python3
import sys
import os
import matplotlib.pyplot as plt
from scapy.all import rdpcap, IP, IPv6, TCP, UDP

def classify_packet(pkt):
    """
    Classifies a packet as upstream or downstream based on port numbers.
    Returns:
      'upstream' if packet is from client to server,
      'downstream' if packet is from server to client,
      None if cannot be classified.
    """
    # Check for IP layer (IPv4 or IPv6)
    if IP in pkt:
        pass
    elif IPv6 in pkt:
        pass
    else:
        return None

    # Look for TCP or UDP layer
    if TCP in pkt:
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
    elif UDP in pkt:
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport
    else:
        return None

    # Apply the heuristic:
    if sport >= 1024 and dport < 1024:
        return "upstream"
    elif sport < 1024 and dport >= 1024:
        return "downstream"
    else:
        return None

def analyze_pcap(pcap_file):
    """
    Reads the pcap file and sums the total bytes for upstream and downstream packets.
    Only packets that can be classified using the heuristic are counted.
    """
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print("Error reading pcap file:", e)
        sys.exit(1)

    upstream_bytes = 0
    downstream_bytes = 0

    for pkt in packets:
        direction = classify_packet(pkt)
        if direction:
            pkt_len = len(pkt)  # total packet length (including headers)
            if direction == "upstream":
                upstream_bytes += pkt_len
            elif direction == "downstream":
                downstream_bytes += pkt_len

    return upstream_bytes, downstream_bytes

def plot_up_vs_down(upstream, downstream):
    """
    Plots a bar chart comparing the total upstream vs downstream bytes.
    Saves the plot as 'upstream_vs_downstream.png' in the same folder as the script.
    """
    categories = ['Upstream', 'Downstream']
    amounts = [upstream, downstream]

    plt.figure(figsize=(6, 6))
    bars = plt.bar(categories, amounts, color=['lightgreen', 'salmon'])
    plt.ylabel("Total Bytes")
    plt.title("Upstream vs Downstream Traffic")

    # Annotate the bars with the exact values
    for bar in bars:
        height = bar.get_height()
        plt.annotate(f'{height:,}',
                     xy=(bar.get_x() + bar.get_width() / 2, height),
                     xytext=(0, 3),  # offset text a bit above the bar
                     textcoords="offset points",
                     ha='center', va='bottom')

    plt.tight_layout()

    # Save the figure in the same directory as the script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    output_file = os.path.join(script_dir, "upstream_vs_downstream.png")
    plt.savefig(output_file)
    plt.show()
    print("Plot saved as:", output_file)

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 upstream_downstream.py <pcap_file>")
        sys.exit(1)

    pcap_file = sys.argv[1]
    upstream, downstream = analyze_pcap(pcap_file)
    print(f"Total Upstream Bytes: {upstream:,}")
    print(f"Total Downstream Bytes: {downstream:,}")
    plot_up_vs_down(upstream, downstream)

if __name__ == "__main__":
    main()
