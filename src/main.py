#!/usr/bin/env python3
import os
import time
import glob
import shutil

# Import your modules (make sure they're in the same folder or in your PYTHONPATH)
import ip_distribution
import Distribution_Pack_Sizes
import plot_inter_arrivals
import tls_v
import top5_ip
import fa
import top_ports


def main():
    # Path to your pcap file; adjust as needed.
    pcap_file = "spotify.pcap"

    # Create an output folder named after the pcap file (without extension)
    pcap_base = os.path.splitext(os.path.basename(pcap_file))[0]
    output_folder = os.path.join(os.getcwd(), pcap_base)
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)
    print("Output folder created:", output_folder)

    # Record start time to later detect files created during this run
    start_time = time.time()

    # Call each module's function (they may display/save plots to the default location)
    print("Plotting distribution of packet sizes...")
    Distribution_Pack_Sizes.plot_packet_size_distribution(pcap_file)

    print("Plotting IP version distribution...")
    rows = ip_distribution.process_pcap(pcap_file)
    ip_distribution.plot_distribution(rows, 'ip_version')

    print("Plotting inter-arrival times...")
    plot_inter_arrivals.plot_inter_arrivals(pcap_file)

    print("Counting and plotting TLS version counts...")
    version_counts = tls_v.count_tls_versions(pcap_file)
    tls_v.plot_tls_version_counts(version_counts)

    print("Plotting top 5 destination IP addresses...")
    top5_ip.plot_top5_destinations(pcap_file)

    print("Analyzing and plotting upstream vs downstream bytes...")
    upstream, downstream = fa.analyze_pcap(pcap_file)
    fa.plot_up_vs_down(upstream, downstream)

    print("Plotting top 20 destination ports...")
    dest_ports = top_ports.analyze_pcap(pcap_file)
    top_ports.plot_top_ports(dest_ports, os.path.basename(pcap_file))

    # Optional: wait a couple of seconds to ensure file modification times are updated
    time.sleep(2)

    # Move all PNG files created during this run to the output folder
    png_files = glob.glob("*.png")
    moved_files = []
    for f in png_files:
        if os.path.getmtime(f) >= start_time:
            dest = os.path.join(output_folder, f)
            shutil.move(f, dest)
            moved_files.append(f)

    print("The following PNG files have been moved to the output folder:")
    for f in moved_files:
        print("  ", f)
    print("All plots are now saved in:", output_folder)


if __name__ == "__main__":
    main()
