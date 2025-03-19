import sys
import os
import matplotlib.pyplot as plt
import pandas as pd
from scapy.all import rdpcap, IP, IPv6, TCP

DEFAULT_HISTOGRAM_BINS = 20

def process_pcap(pcap_file):
    """
    Reads packets from the pcap file, collects various IP/TCP fields,
    and returns a list of dictionaries for each packet.
    """
    if not os.path.isfile(pcap_file):
        print(f"Error: File '{pcap_file}' does not exist.")
        sys.exit(1)

    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"Error reading pcap file '{pcap_file}': {e}")
        sys.exit(1)

    rows = []
    previous_timestamp = None

    for packet in packets:
        row = {}

        # Check if this is an IPv4 packet
        if IP in packet:
            ip_layer = packet[IP]
            row['ip_version'] = 4
            row['ip_src'] = ip_layer.src
            row['ip_dst'] = ip_layer.dst
            row['ip_ihl'] = ip_layer.ihl
            row['ip_tos'] = ip_layer.tos
            row['ip_len'] = ip_layer.len
            row['ip_id'] = ip_layer.id
            row['ip_flags'] = ip_layer.flags
            row['ip_frag'] = ip_layer.frag
            row['ip_ttl'] = ip_layer.ttl
            row['ip_proto'] = ip_layer.proto
            row['ip_chksum'] = ip_layer.chksum

        # Check if this is an IPv6 packet
        elif IPv6 in packet:
            ipv6_layer = packet[IPv6]
            row['ip_version'] = 6
            row['ip_src'] = ipv6_layer.src
            row['ip_dst'] = ipv6_layer.dst
            row['ip_tos'] = ipv6_layer.tc  # traffic class
            row['ip_len'] = ipv6_layer.plen  # payload length
            row['ip_proto'] = ipv6_layer.nh  # next header
            row['ip_hlim'] = ipv6_layer.hlim  # hop limit
            row['ip_ihl'] = None
            row['ip_id'] = None
            row['ip_flags'] = None
            row['ip_frag'] = None
            row['ip_ttl'] = None
            row['ip_chksum'] = None
        else:
            # If neither IPv4 nor IPv6:
            row['ip_version'] = None
            row['ip_src'] = None
            row['ip_dst'] = None
            row['ip_ihl'] = None
            row['ip_tos'] = None
            row['ip_len'] = None
            row['ip_id'] = None
            row['ip_flags'] = None
            row['ip_frag'] = None
            row['ip_ttl'] = None
            row['ip_proto'] = None
            row['ip_chksum'] = None

        # TCP layer fields
        if TCP in packet:
            tcp_layer = packet[TCP]
            row['tcp_sport'] = tcp_layer.sport
            row['tcp_dport'] = tcp_layer.dport
            row['tcp_seq'] = tcp_layer.seq
            row['tcp_ack'] = tcp_layer.ack
            row['tcp_dataofs'] = tcp_layer.dataofs
            row['tcp_reserved'] = tcp_layer.reserved
            row['tcp_flags'] = tcp_layer.flags
            row['tcp_window'] = tcp_layer.window
            row['tcp_chksum'] = tcp_layer.chksum
            row['tcp_urgptr'] = tcp_layer.urgptr
        else:
            row['tcp_sport'] = None
            row['tcp_dport'] = None
            row['tcp_seq'] = None
            row['tcp_ack'] = None
            row['tcp_dataofs'] = None
            row['tcp_reserved'] = None
            row['tcp_flags'] = None
            row['tcp_window'] = None
            row['tcp_chksum'] = None
            row['tcp_urgptr'] = None

        # Packet size
        row['packet_size'] = len(packet)

        # Inter-packet time
        if previous_timestamp is None:
            row['inter_arrival'] = 0
        else:
            row['inter_arrival'] = packet.time - previous_timestamp
        previous_timestamp = packet.time

        # Flow key for TCP in IPv4/IPv6
        if TCP in packet:
            if row['ip_version'] == 4 or row['ip_version'] == 6:
                row['flow_key'] = (
                    row['ip_src'],
                    row['ip_dst'],
                    row['tcp_sport'],
                    row['tcp_dport']
                )
            else:
                row['flow_key'] = None
        else:
            row['flow_key'] = None

        rows.append(row)

    # Calculate TCP flow sizes
    flow_counts = {}
    for row in rows:
        if row['flow_key'] is not None:
            flow_counts[row['flow_key']] = flow_counts.get(row['flow_key'], 0) + 1

    for row in rows:
        if row['flow_key'] is not None:
            row['flow_size'] = flow_counts[row['flow_key']]
        else:
            row['flow_size'] = 0

    return rows

def plot_distribution(rows, column_name):
    """
    Plots a histogram or bar chart of the specified column_name from rows.
    For 'ip_version', it plots a simple bar chart for IPv4 vs IPv6.
    """
    df = pd.DataFrame(rows)

    if column_name not in df.columns:
        print(f"Column '{column_name}' not found in DataFrame.")
        return

    data = df[column_name].dropna()
    if data.empty:
        print(f"No data found in column '{column_name}'.")
        return

    # Special handling for 'ip_version'
    if column_name == 'ip_version':
        data = data[data.isin([4, 6])]
        if data.empty:
            print("No IPv4/IPv6 packets found.")
            return
        counts = data.value_counts()

        plt.figure(figsize=(10, 6))
        plt.bar(counts.index.astype(str), counts.values, edgecolor='black')
        plt.title("Distribution of IP Version (4 vs. 6)")
        plt.xlabel("IP Version")
        plt.ylabel("Count")
        plt.tight_layout()
        plt.show()
        return

    # For numeric columns
    if pd.api.types.is_numeric_dtype(data):
        plt.figure(figsize=(10, 6))
        plt.hist(data, bins=DEFAULT_HISTOGRAM_BINS, edgecolor='black')
        plt.title(f"Distribution of {column_name}")
        plt.xlabel(column_name)
        plt.ylabel("Frequency")
        plt.tight_layout()
        plt.show()
    else:
        # For categorical data
        value_counts = data.value_counts()
        if value_counts.empty:
            print(f"No categorical data found for column '{column_name}'.")
            return

        plt.figure(figsize=(10, 6))
        plt.bar(value_counts.index.astype(str), value_counts.values, edgecolor='black')
        plt.title(f"Distribution of {column_name}")
        plt.xlabel(column_name)
        plt.ylabel("Count")
        plt.tight_layout()
        plt.show()

def main():
    """
    Usage: python ip_distribution.py <pcap_file>
    """
    if len(sys.argv) != 2:
        print("Usage: python ip_distribution.py <pcap_file>")
        sys.exit(1)

    pcap_file = sys.argv[1]
    row_data = process_pcap(pcap_file)
    plot_distribution(row_data, 'ip_version')

if __name__ == "__main__":
    main()
