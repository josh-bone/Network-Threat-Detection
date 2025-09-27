"""
utils.py
This module provides utility functions for analyzing PCAP files and extracting Indicators of Compromise (IOCs) such as IP addresses and domain names. It leverages the PyShark library for packet capture and parsing, and integrates with external APIs (e.g., ipinfo.io) to enrich IP address data.
Main functionalities include:
- Capturing live network packets and saving them to a file.
- Loading and parsing PCAP files.
- Extracting unique IP addresses and domain names from packet captures.
- Querying external services for additional IP address information.
- Assembling and saving analysis reports in JSON format.
Logging is used throughout for debugging and informational purposes.
"""
# Standard imports
from datetime import datetime
import json
import os
import sys
import logging

# Third-party imports
import pyshark
import requests

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


def load_pcap(file_path) -> pyshark.capture.file_capture.FileCapture:
    """
    Loads a PCAP file and returns a PyShark FileCapture object for packet analysis.

        file_path (str): The path to the PCAP file to be loaded.

        pyshark.capture.file_capture.FileCapture: An object representing the captured packets from the PCAP file.

    Raises:
        FileNotFoundError: If the specified file_path does not exist.
        pyshark.capture.capture.TSharkCrashException: If tshark fails to process the file.
    """
    assert os.path.exists(file_path), f"File {file_path} does not exist"
    cap = pyshark.FileCapture(file_path)
    return cap


def extract_ips(cap):
    """
    Extracts unique source and destination IP addresses from a packet capture.
    Iterates over all packets in the provided capture object, attempting to extract
    the source and destination IP addresses from each packet's IP layer. If a packet
    does not contain an IP layer, it is skipped. Logs progress and any packets
    without an IP layer.
    Args:
        cap: An iterable packet capture object, where each packet is expected to have
             an 'ip' attribute with 'src' and 'dst' fields.
    Returns:
        set: A set of unique IP addresses (as strings) found in the capture.
    """

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
    """
    Extracts unique domain names from DNS packets in a given packet capture.
    Iterates over the provided packet capture object, inspects each packet for DNS queries,
    and collects the queried domain names into a set to ensure uniqueness.
    Args:
        cap (iterable): An iterable of packet objects, each potentially containing DNS information.
    Returns:
        set: A set of unique domain names (as strings) extracted from DNS query packets.
    """

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


def assemble_report(ips, domains, ip_info=None) -> dict:
    """
    Assembles a report containing unique IPs, domains, and optional IP information.
    Args:
        ips (Iterable): A collection of unique IP addresses.
        domains (Iterable): A collection of unique domain names.
        ip_info (Optional[Any]): Additional information about the IPs (default is None).
    Returns:
        dict: A dictionary containing the report with the following keys:
            - "save_time": ISO formatted timestamp of report creation.
            - "unique_ips": List of unique IP addresses.
            - "unique_domains": List of unique domain names.
            - "ip_info": (Optional) Additional IP information if provided.
    """

    report = {
        "save_time": datetime.now().isoformat(),
        "unique_ips": list(ips),
        "unique_domains": list(domains),
    }

    if ip_info is not None:
        report["ip_info"] = ip_info

    return report


def save_report(report: dict, out_file: str | os.PathLike) -> None:
    """
    Saves the given report as a JSON file.
    Args:
        report (dict): The report data to be saved.
        out_file (str or Path): The file path where the report will be saved.
    Raises:
        TypeError: If the report is not serializable to JSON.
        OSError: If the file cannot be written.
    """

    try:
        with open(out_file, "w", encoding='utf-8') as f:
            json.dump(report, f, indent=4)
    except IOError as e:
        print(f"Error writing to file {out_file}: {e}")
    except TypeError as e:  # Catch JSON serialization errors
        print(f"Error serializing report to JSON: {e}")
    except Exception as e:  # Catch other potential file-related errors
        print(f"An unexpected error occurred during file operation: {e}")
        raise e


def analyze_file(in_file, out_file=None) -> dict:
    """
    Wrapper for the analyze() function. Takes an input pcap file, loads it, and analyzes it.
    Args:
        in_file (str): Path to the input pcap file to be analyzed.
        out_file (str, optional): Path to the output file where analysis results will be saved. Defaults to None.
    Returns:
        dict: The result of the analysis, as returned by the `analyze` function.
    Raises:
        FileNotFoundError: If the input file does not exist.
        Exception: If an error occurs during loading or analysis of the pcap file.
    """

    logger.info(f"Loading pcap file {in_file}")  # debugging
    cap = load_pcap(in_file)
    logger.info(f"Loaded pcap file {in_file}")  # debugging

    return analyze(cap, out_file=out_file)


def analyze(cap, out_file=None) -> dict:
    """
    Analyzes a pcap capture object to extract unique IP addresses and domains, gathers information about each IP,
    and generates a report. Optionally saves the report to a specified output file.
    Args:
        cap: The pcap capture object to analyze.
        out_file (str, optional): Path to save the generated report. If None, the report is not saved to disk.
    Returns:
        dict: The assembled report containing extracted IPs, domains, and IP information.
    """

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

    report = assemble_report(ips, domains, ip_info=ip_info)
    if out_file is not None:
        save_report(report, out_file=out_file)
        print(f"Report saved to {out_file}")
        logger.info(f"Report saved to {out_file}")

    return report
