import matplotlib.pyplot as plt
from scapy.all import rdpcap, IP, IPv6
from collections import Counter


def plot_top5_destinations(pcap_file_path):
    """
    This function takes a path to a pcap/pcapng file,
    extracts both IPv4 and IPv6 packets, collects destination addresses,
    and displays a graph of the top 5 most frequent destination addresses.
    """
    # Read packets from the file
    packets = rdpcap(pcap_file_path)
    dest_addresses = []

    # Process each packet and check for IPv4 or IPv6 layer
    for pkt in packets:
        if IP in pkt:
            dest_addresses.append(pkt[IP].dst)
        elif IPv6 in pkt:
            dest_addresses.append(pkt[IPv6].dst)

    if not dest_addresses:
        print("No IPv4 or IPv6 packets found in the file.")
        return

    # Count frequency of destination addresses
    counts = Counter(dest_addresses)
    top5 = counts.most_common(5)

    addresses, freqs = zip(*top5)

    # Plotting the bar chart for the top 5 destination addresses
    plt.figure(figsize=(10, 6))
    plt.bar(addresses, freqs)
    plt.title("Top 5 Destination IP Addresses")
    plt.xlabel("Destination IP Address")
    plt.ylabel("Frequency")
    # Rotate x-axis labels for better readability
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    plt.show()


# Example call (replace with your actual file path):
# plot_top5_destinations("path/to/your/file.pcapng")

if __name__ == "__main__":
# דוגמה לשימוש:
    plot_top5_destinations(r"C:\Users\jhon\Downloads\Telegram Desktop\googleMEETS.pcap")
