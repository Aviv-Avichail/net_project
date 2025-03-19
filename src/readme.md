# Network Analysis Project
עידו כהן 322541327
יהונתן עובדיה 206574931
אביב אביחיל 215203951
דוד בלוך 214857468
This project contains a set of Python scripts designed for analyzing network traffic from `.pcap` or `.pcapng` files. Each script provides different insights, such as packet size distributions, packet timings, IP usage, and more. You can run the scripts individually or use the provided `main.py` to execute all analyses in one go.

## Overview of Scripts

- **Distribution_Pack_Sizes.py**  
  Generates a histogram showing how packet sizes (in bytes) are distributed.

- **plot_inter_arrivals.py**  
  Calculates and plots the time intervals between packets, focusing on intervals up to the 99th percentile.

- **ip_distribution.py**  
  Determines the proportion of IPv4 and IPv6 packets and plots their distribution. Can easily be modified to analyze other attributes.

- **top5_ip.py**  
  Identifies and plots the top five destination IP addresses from the captured traffic.

- **top_ports.py**  
  Shows the most common TCP/UDP destination ports, highlighting the top 20.

- **fa.py** (Flow Analysis)  
  Classifies packets as upstream or downstream based on port heuristics and plots the total data transferred in each direction.

- **main.py**  
  A script that automatically runs all of the above analyses and saves the resulting plots in a dedicated folder named after your `.pcap` file.

## Requirements

- Python 3.6 or newer (Python 3.8 recommended)
- Required libraries:
  - scapy
  - matplotlib
  - pandas (only for `ip_distribution.py`)

Install with:
```bash
pip install scapy matplotlib pandas
```

## Running the Scripts

### Using the Main Script

Running `main.py` executes all analyses automatically. The results (plots) will be saved in a folder named after your `.pcap` file.

```bash
python main.py <pcap_file>
```

For example:
```bash
python main.py example.pcap
```

You’ll find a new folder (`example`) containing all generated plots.

### Running Individual Scripts

You can run each script separately if you prefer specific analyses:

1. **Packet Size Distribution**
   ```bash
   python Distribution_Pack_Sizes.py <pcap_file>
   ```
2. **Packet Inter-Arrival Times**
   ```bash
   python plot_inter_arrivals.py <pcap_file>
   ```
3. **IPv4 vs IPv6 Distribution**
   ```bash
   python ip_distribution.py <pcap_file>
   ```
4. **Top 5 IP Addresses**
   ```bash
   python top5_ip.py <pcap_file>
   ```
5. **Top 20 Destination Ports**
   ```bash
   python top_ports.py <pcap_file>
   ```
6. **Upstream and Downstream Data Analysis**
   ```bash
   python upstream_downstream.py <pcap_file>
   ```

## Important Notes

- Scripts will notify you with an error message if the provided `.pcap` file doesn't exist.
- Some analyses (e.g., inter-arrival times) require at least two packets to be meaningful.
- Processing large `.pcap` files may take longer, depending on your computer specs.
- If the script finds no relevant data (for example, no IPv6 packets), you'll get a clear message rather than an empty plot.

