import pyshark
import json
import argparse
import requests
import os
import sys
import logging
from datetime import datetime

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


def get_ip_info(ip_address: str) -> dict | Exception:
    """Calls out to an API at ipinfo.io to get information about an IP address.

    Args:
        ip_address (str): The IP address to look up.

    Returns:
        dict | Exception: A dictionary with IP information or an Exception if the request fails.
    """
    try:
        # Using ipinfo.io API for IP data
        url = f"https://ipinfo.io/{ip_address}/json"
        response = requests.get(url)
        response.raise_for_status()  # Raise HTTPError for bad responses
        ip_info = response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching IP info: {str(e)}")
        return e

    return ip_info


def capture_packets(
    output_filename: str, interface="en0", bpf_filter=None, duration=10
):
    """Takes a live capture with PyShark

    Args:
        output_filename (str): The file to save the capture to. If None, we won't save to a file.
        interface (str, optional): interface on which we capture. Defaults to "en0".
        bpf_filter (_type_, optional): wireshark filter, e.g. "udp port 555". Defaults to None.
        duration (int, optional): Length of capture in seconds. Defaults to 10.

    Returns:
        pyshark capture object (idk the real name): you can iterate over this to get individual packets.
    """
    assert duration is not None and duration > 0, "Duration must be a positive integer"

    logger.info(
        f"Starting live capture on interface {interface} for {duration} seconds"
    )
    try:
        capture = pyshark.LiveCapture(
            interface=interface, bpf_filter=bpf_filter, output_file=output_filename
        )
        capture.sniff(timeout=duration)
    except KeyboardInterrupt:
        print("\nCtrl-C pressed. Exiting gracefully.")
        sys.exit(0)  # Explicitly exit the program

    logger.info(f"Capture finished, saving to {output_filename}")
    logger.info(f"Captured {len(capture)} packets on interface {interface}")

    return capture


def load_pcap(file_path):
    cap = pyshark.FileCapture(file_path)
    return cap


def extract_ips(cap):
    ips = set()
    for i, pkt in enumerate(cap):
        logger.info(f"Extracting IPs from packet {i}/{len([p for p in cap])}")
        try:
            src = pkt.ip.src
            dst = pkt.ip.dst
            ips.add(src)
            ips.add(dst)
        except AttributeError:
            logger.info(f"Packet {i} has no IP layer, skipping")
            continue  # Packet has no IP layer
    return ips


def extract_domains(cap):
    domains = set()
    for i, pkt in enumerate(cap):
        logger.info(f"Extracting domains from packet {i}/{len([p for p in cap])}")
        if "DNS" in pkt:
            try:
                query = pkt.dns.qry_name
                domains.add(query)
            except AttributeError:
                continue
    return domains


def save_report(ips, domains, out_file, ip_info=None):

    report = {
        "save_time": datetime.now().isoformat(),
        "unique_ips": list(ips),
        "unique_domains": list(domains),
    }

    if ip_info is not None:
        report["ip_info"] = ip_info

    with open(out_file, "w") as f:
        json.dump(report, f, indent=4)


def analyze_file(in_file, out_file=None):
    logger.info(f"Loading pcap file {in_file}")  # debugging
    cap = load_pcap(in_file)
    logger.info(f"Loaded pcap file {in_file}")  # debugging

    return analyze(cap, out_file=out_file)


def analyze(cap, out_file=None):

    logger.info(f"Extracting IPs and domains")  # debugging
    ips = extract_ips(cap)
    logger.info(f"Extracted {len(ips)} unique IPs")  # debugging

    logger.info(f"Extracting Domains")  # debugging
    domains = extract_domains(cap)
    logger.info(f"Extracted {len(domains)} unique domains")  # debugging

    ip_info = [get_ip_info(ip_address=addr) for addr in ips]

    # END FILE CAPTURE OBJ
    logger.info(f"Closing pcap object")  # debugging
    cap.close()
    logger.info(f"Closed pcap object")  # debugging

    if out_file is not None:
        save_report(ips, domains, out_file, ip_info=ip_info)
        print(f"Report saved to {out_file}")
        logger.info(f"Report saved to {out_file}")
