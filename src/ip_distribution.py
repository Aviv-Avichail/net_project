import matplotlib.pyplot as plt
import pandas as pd
from scapy.all import rdpcap, IP, IPv6, TCP


def process_pcap(pcap_file):
    packets = rdpcap(pcap_file)
    rows = []
    prev_time = None

    for pkt in packets:
        row = {}

        # בדיקה אם זו חבילת IPv4
        if IP in pkt:
            ip_layer = pkt[IP]
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

        # בדיקה אם זו חבילת IPv6
        elif IPv6 in pkt:
            ipv6_layer = pkt[IPv6]
            row['ip_version'] = 6
            row['ip_src'] = ipv6_layer.src
            row['ip_dst'] = ipv6_layer.dst
            # ב-IPv6 אין את כל השדות כמו ב-IPv4,
            # אז אפשר למלא רק מה שרלוונטי:
            row['ip_tos'] = ipv6_layer.tc  # traffic class
            row['ip_len'] = ipv6_layer.plen  # payload length
            row['ip_proto'] = ipv6_layer.nh  # next header
            row['ip_hlim'] = ipv6_layer.hlim  # hop limit
            # שדות שאינם רלוונטיים / לא קיימים ב-IPv6 אפשר להציב None
            row['ip_ihl'] = None
            row['ip_id'] = None
            row['ip_flags'] = None
            row['ip_frag'] = None
            row['ip_ttl'] = None
            row['ip_chksum'] = None
        else:
            # אם לא IP ולא IPv6:
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

        # --- TCP ---
        if TCP in pkt:
            tcp_layer = pkt[TCP]
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

        # --- גודל המנה ---
        row['packet_size'] = len(pkt)

        # --- זמן בין מנות ---
        if prev_time is None:
            row['inter_arrival'] = 0
        else:
            row['inter_arrival'] = pkt.time - prev_time
        prev_time = pkt.time

        # Mפלח זרימה (Flow Key) ל-TCP עבור IPv4/IPv6
        if TCP in pkt:
            if IP in pkt:
                row['flow_key'] = (pkt[IP].src, pkt[IP].dst, pkt[TCP].sport, pkt[TCP].dport)
            elif IPv6 in pkt:
                row['flow_key'] = (pkt[IPv6].src, pkt[IPv6].dst, pkt[TCP].sport, pkt[TCP].dport)
            else:
                row['flow_key'] = None
        else:
            row['flow_key'] = None

        rows.append(row)

    # חישוב גודל זרימה עבור TCP
    flow_counts = {}
    for row in rows:
        flow_key = row['flow_key']
        if flow_key is not None:
            flow_counts[flow_key] = flow_counts.get(flow_key, 0) + 1

    for row in rows:
        if row['flow_key'] is not None:
            row['flow_size'] = flow_counts[row['flow_key']]
        else:
            row['flow_size'] = 0

    return rows


def plot_distribution(rows, column_name):
    df = pd.DataFrame(rows)

    if column_name not in df.columns:
        print(f"Column '{column_name}' not found in DataFrame.")
        return

    data = df[column_name].dropna()
    if data.empty:
        print(f"No data in column '{column_name}'.")
        return

    # טיפול מיוחד בעמודת ip_version
    if column_name == 'ip_version':
        # נתייחס רק לערכים 4 ו-6
        data = data[data.isin([4, 6])]
        if data.empty:
            print("No IPv4/IPv6 found.")
            return

        counts = data.value_counts()
        plt.bar(counts.index.astype(str), counts.values)
        plt.title("Distribution of IP Version (4 vs. 6)")
        plt.xlabel("IP Version")
        plt.ylabel("Count")
        plt.tight_layout()
        plt.show()
        return

    # עבור עמודות אחרות (או אם תרצו טיפול כללי)
    if pd.api.types.is_numeric_dtype(data):
        plt.hist(data, bins=20)
        plt.title(f"Distribution of {column_name}")
        plt.xlabel(column_name)
        plt.ylabel("Frequency")
    else:
        counts = data.value_counts()
        plt.bar(counts.index.astype(str), counts.values)
        plt.title(f"Distribution of {column_name}")
        plt.xlabel(column_name)
        plt.ylabel("Count")
    plt.tight_layout()
    plt.show()


if __name__ == "__main__":

    pcap_file = r"C:\Users\jhon\Downloads\Telegram Desktop\googleMEETS.pcap"
    rows = process_pcap(pcap_file)

    # כעת, plot_distribution אמור להראות התפלגות 4 מול 6 אם יש IPv4/IPv6
    plot_distribution(rows, 'ip_version')
