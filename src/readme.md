

# Network Analysis Project

This project provides multiple Python scripts to analyze network traffic from `.pcap` or `.pcapng` files. Each script focuses on a different aspect of the traffic (e.g., packet size distribution, inter-arrival times, IP version distribution, etc.). You can run each script individually or use the main script (`main.py`) to run them all at once.

## 1. Project Overview

- **Distribution_Pack_Sizes.py**  
  Plots a histogram showing the distribution of packet sizes in bytes.

- **plot_inter_arrivals.py**  
  Calculates the time between consecutive packets and plots the inter-arrival time distribution (up to the 99th percentile).

- **ip_distribution.py**  
  Identifies whether packets are IPv4 or IPv6 and plots the distribution of IP versions. Can be adapted to plot other columns as well.

- **top5_ip.py**  
  Finds the top five most frequently used destination IP addresses (IPv4 or IPv6) and plots them.

- **top_ports.py**  
  Determines the most common TCP/UDP destination ports and plots the top 20.

- **fa.py** (Flow Analysis)  
  Uses a heuristic to classify packets as upstream or downstream (based on port numbers) and plots the total byte count for each direction.

- **main.py**  
  A convenience script that runs all of the above analyses in sequence, saving any generated plots into a folder named after your `.pcap` file.

## 2. Prerequisites

- **Python 3.6+** (recommended 3.8 or higher).
- **Packages**:
  - [scapy](https://pypi.org/project/scapy/)
  - [matplotlib](https://pypi.org/project/matplotlib/)
  - [pandas](https://pypi.org/project/pandas/) (required by `ip_distribution.py`)

Install them using:
```bash
pip install scapy matplotlib pandas
```

## 3. How to Run

### A. Main Script (Recommended)

Running `main.py` will sequentially call all analysis scripts and save their output (plots) into a new folder named after the `.pcap` file.

```bash
python main.py <pcap_file>
```

Example:
```bash
python main.py example.pcap
```

After completion, you will see a folder named `example` (matching your input file name) containing all generated `.png` plots.

### B. Individual Scripts

You can also run each script separately if you only need specific plots:

1. **Distribution of Packet Sizes**  
   ```bash
   python Distribution_Pack_Sizes.py <pcap_file>
   ```
2. **Inter-Arrival Times**  
   ```bash
   python plot_inter_arrivals.py <pcap_file>
   ```
3. **IP Version Distribution**  
   ```bash
   python ip_distribution.py <pcap_file>
   ```
4. **Top 5 Destination IPs**  
   ```bash
   python top5_ip.py <pcap_file>
   ```
5. **Top 20 Destination Ports**  
   ```bash
   python top_ports.py <pcap_file>
   ```
6. **Upstream vs Downstream Bytes**  
   ```bash
   python upstream_downstream.py <pcap_file>
   ```

## 4. Notes & Edge Cases

- Scripts check if the file exists before parsing. If it doesn’t, you’ll see an error message.
- Some scripts require at least 2 packets to produce meaningful results (e.g., `plot_inter_arrivals.py`).
- Large `.pcap` files may take some time to process, depending on system resources.
- If no data matches a script’s criteria (e.g., no IPv6 traffic), the script will display a message instead of a plot.
