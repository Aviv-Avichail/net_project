#!/usr/bin/env python3
import os
import sys
import time
import glob
import shutil

import ip_distribution
import Distribution_Pack_Sizes
import plot_inter_arrivals
import top5_ip
import upstream_downstream
import top_ports

WAIT_TIME_SECONDS = 2
IMAGE_EXTENSION = ".png"

def main():
    """
    Main entry point for generating all analysis plots and organizing them in an output folder.
    Usage: python main.py <pcap_file>
    """
    if len(sys.argv) != 2:
        print("Usage: python main.py <pcap_file>")
        sys.exit(1)

    pcap_file = sys.argv[1]

    # Check if file exists before proceeding
    if not os.path.isfile(pcap_file):
        print(f"Error: File '{pcap_file}' does not exist.")
        sys.exit(1)

    # Create an output folder named after the pcap file (without extension)
    pcap_base = os.path.splitext(os.path.basename(pcap_file))[0]
    output_folder = os.path.join(os.getcwd(), pcap_base)
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)
    print("Output folder created:", output_folder)

    # Record start time to detect files created during this run
    start_time = time.time()

    # Call each module's function
    print("Plotting distribution of packet sizes...")
    Distribution_Pack_Sizes.plot_packet_size_distribution(pcap_file)

    print("Plotting IP version distribution...")
    rows = ip_distribution.process_pcap(pcap_file)
    ip_distribution.plot_distribution(rows, 'ip_version')

    print("Plotting inter-arrival times...")
    plot_inter_arrivals.plot_inter_arrivals(pcap_file)

    print("Plotting top 5 destination IP addresses...")
    top5_ip.plot_top5_destinations(pcap_file)

    print("Analyzing and plotting upstream vs downstream bytes...")
    upstream_bytes, downstream_bytes = upstream_downstream.analyze_pcap(pcap_file)
    upstream_downstream.plot_up_vs_down(upstream_bytes, downstream_bytes)

    print("Plotting top 20 destination ports...")
    destination_ports = top_ports.analyze_pcap(pcap_file)
    top_ports.plot_top_ports(destination_ports, os.path.basename(pcap_file))

    # Optional: wait to ensure file modification times are updated
    time.sleep(WAIT_TIME_SECONDS)

    # Move all PNG files created during this run to the output folder
    png_files = glob.glob(f"*{IMAGE_EXTENSION}")
    moved_files = []
    for image_file in png_files:
        # If it was created/modified during this run
        if os.path.getmtime(image_file) >= start_time:
            destination = os.path.join(output_folder, image_file)
            shutil.move(image_file, destination)
            moved_files.append(image_file)

    print("The following PNG files have been moved to the output folder:")
    for moved_file in moved_files:
        print("  ", moved_file)
    print("All plots are now saved in:", output_folder)

if __name__ == "__main__":
    main()
