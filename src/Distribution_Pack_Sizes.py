import matplotlib.pyplot as plt
from scapy.all import rdpcap


def plot_packet_size_distribution(pcap_path):
    """
    Reads a pcap/pcapng file from the given path, extracts packet sizes,
    and plots a histogram of their distribution.

    Parameters:
        pcap_path (str): The file path to the pcap/pcapng file.
    """
    # Read all packets from the file
    packets = rdpcap(pcap_path)

    # Get the size (in bytes) of each packet
    packet_sizes = [len(pkt) for pkt in packets]

    # Plot histogram
    plt.figure(figsize=(10, 6))
    plt.hist(packet_sizes, bins=50, edgecolor='black')
    plt.xlabel("Packet Size (bytes)")
    plt.ylabel("Number of Packets")
    plt.title("Distribution of Packet Sizes")
    plt.grid(True)
    plt.show()


# דוגמה לשימוש:
#plot_packet_size_distribution(r"C:\Users\jhon\PycharmProjects\network_avi\youyube (2).pcap")
# plot_packet_size_distribution("example.pcap")
