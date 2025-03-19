import matplotlib.pyplot as plt
import scapy
from pyshark.packet import packet
from scapy.all import rdpcap, IP, IPv6
import numpy as np
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6

from collections import Counter


def plot_inter_arrivals(pcap_file):


    """
    פונקציה שמקבלת קובץ pcap/pcapng (נתיב מלא),
    מחשבת את ה-Inter-Arrival Times בין מנות עוקבות ומציגה היסטוגרמה.
    בלי שימוש ב-np.percentile, אלא חישוב ידני של האחוזון.
    """

    packets = rdpcap(pcap_file)

    # אם פחות מ-2 חבילות, לא ניתן לחשב הפרשי זמנים
    if len(packets) < 2:
        print("אין מספיק חבילות (פחות מ-2) לחישוב Inter-Arrival Times.")
        return

    # רשימת הפרשי הזמנים בין כל שתי מנות עוקבות
    inter_arrivals = []
    for i in range(1, len(packets)):
        delta = packets[i].time - packets[i-1].time
        inter_arrivals.append(delta)

    # הסרת ערכים שליליים
    inter_arrivals = [t for t in inter_arrivals if t >= 0]

    if not inter_arrivals:
        print("לא נמצאו ערכי Inter-Arrival חוקיים (כולם היו שליליים).")
        return

    # הפיכת הרשימה ל-numpy array לצורך נוחות, לא חובה.
    arr = np.array(inter_arrivals)

    # חשב ידנית את האחוזון 99:
    arr_sorted = np.sort(arr)
    idx_99 = int(len(arr_sorted) * 0.99)  # מיקום שמייצג את ה-99%
    cutoff_99 = arr_sorted[idx_99]       # ערך שממנו ומעלה נחתוך

    # מסננים מהמערך את הערכים הגדולים יותר מהcutoff
    arr_filtered = arr[arr <= cutoff_99]

    if arr_filtered.size == 0:
        print("כל ערכי ה-Inter-Arrival היו מעל האחוזון ה-99, אין מה להציג.")
        return

    # ציור היסטוגרמה עם הערכים המסוננים
    plt.hist(arr_filtered, bins=30)
    plt.title("Distribution of Inter-Arrival Times (<= 99th percentile)")
    plt.xlabel("Inter-Arrival Time (seconds)")
    plt.ylabel("Frequency")
    plt.tight_layout()
    plt.show()


import matplotlib.pyplot as plt
import pandas as pd
from scapy.all import rdpcap, IP, IPv6, TCP

import pyshark
import matplotlib.pyplot as plt
from collections import Counter





# Example usage:
# plot_tls_versions('path_to_your_file.pcap')

if __name__ == "__main__":
    pcap_file= r"C:\Users\jhon\Downloads\Telegram Desktop\googleMEETS.pcap"
    plot_inter_arrivals(pcap_file)

