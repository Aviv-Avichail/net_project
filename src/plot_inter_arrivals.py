import sys
import os
import matplotlib.pyplot as plt
import numpy as np
from scapy.all import rdpcap

MIN_REQUIRED_PACKETS = 2
PERCENTILE_THRESHOLD = 0.99
HISTOGRAM_BINS = 30

def plot_inter_arrivals(pcap_file):
    """
    Reads a pcap/pcapng file, calculates inter-arrival times between consecutive packets,
    and displays a histogram (up to the 99th percentile).
    """
    if not os.path.isfile(pcap_file):
        print(f"Error: File '{pcap_file}' does not exist.")
        return

    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"Error reading pcap file '{pcap_file}': {e}")
        return

    # If there are not enough packets, we cannot compute inter-arrival times.
    if len(packets) < MIN_REQUIRED_PACKETS:
        print(f"Not enough packets (less than {MIN_REQUIRED_PACKETS}) to compute inter-arrival times.")
        return

    # Calculate time deltas between consecutive packets.
    inter_arrival_times = []
    for i in range(1, len(packets)):
        delta_time = packets[i].time - packets[i - 1].time
        inter_arrival_times.append(delta_time)

    # Remove any negative values (edge case).
    inter_arrival_times = [t for t in inter_arrival_times if t >= 0]
    if not inter_arrival_times:
        print("No valid inter-arrival times found (all were negative).")
        return

    inter_arrival_array = np.array(inter_arrival_times)
    sorted_times = np.sort(inter_arrival_array)

    # Find the cutoff for the PERCENTILE_THRESHOLD.
    cutoff_index = int(len(sorted_times) * PERCENTILE_THRESHOLD)
    cutoff_value = sorted_times[cutoff_index]

    # Filter out values greater than the cutoff.
    filtered_times = inter_arrival_array[inter_arrival_array <= cutoff_value]
    if filtered_times.size == 0:
        print(f"All inter-arrival values were above the {PERCENTILE_THRESHOLD * 100}th percentile.")
        return

    plt.figure(figsize=(10, 6))
    plt.hist(filtered_times, bins=HISTOGRAM_BINS, edgecolor='black')
    plt.title(f"Distribution of Inter-Arrival Times (<= {int(PERCENTILE_THRESHOLD * 100)}th percentile)")
    plt.xlabel("Inter-Arrival Time (seconds)")
    plt.ylabel("Frequency")
    plt.tight_layout()
    plt.show()

def main():
    """
    Usage: python plot_inter_arrivals.py <pcap_file>
    """
    if len(sys.argv) != 2:
        print("Usage: python plot_inter_arrivals.py <pcap_file>")
        sys.exit(1)

    pcap_file = sys.argv[1]
    plot_inter_arrivals(pcap_file)

if __name__ == "__main__":
    main()
