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
        response = requests.get(url, timeout=5)
        response.raise_for_status()  # Raise HTTPError for bad responses
        ip_info = response.json()
    except requests.exceptions.RequestException as e:
        logger.error("Error fetching IP info: %s", str(e))
        return e

    return ip_info


def is_number(s) -> bool:
    """Check if the input string is a number (int or float)."""
    if s is None:
        return False
    try:
        float(s)
        return True
    except ValueError:
        return False


def capture_packets(
    output_filename: str = None, interface="en0", bpf_filter=None, duration=10
) -> pyshark.capture.live_capture.LiveCapture:
    """Takes a live capture with PyShark

    Args:
        output_filename (str): The file to save the capture to. If None, we won't save to a file.
        interface (str, optional): interface on which we capture. Defaults to "en0".
        bpf_filter (_type_, optional): wireshark filter, e.g. "udp port 555". Defaults to None.
        duration (int, optional): Length of capture in seconds. Defaults to 10.

    Returns:
        pyshark capture object (idk the real name): you can iterate over this to get individual packets.
    """
    if duration <= 0 or not is_number(duration):
        raise ValueError("Duration must be a positive integer")

    logger.info(
        "Starting live capture on interface %s for %d seconds", interface, duration
    )
    try:
        capture = pyshark.LiveCapture(
            interface=interface, bpf_filter=bpf_filter, output_file=output_filename
        )
        capture.sniff(timeout=duration)
    except KeyboardInterrupt:
        print("\nCtrl-C pressed. Exiting gracefully.")
        sys.exit(0)  # Explicitly exit the program

    logger.info("Capture finished, saving to %s", output_filename)
    logger.info("Captured %d packets on interface %s", len(capture), interface)

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
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"PCAP file {file_path} does not exist")

    cap = pyshark.FileCapture(file_path)
    return cap


def extract_ips(cap) -> set:
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

    ip_counts = {}
    for i, pkt in enumerate(cap):
        logger.info("Extracting IPs from packet %d/%d", i, len(list(cap)))
        try:
            src = pkt.ip.src
            dst = pkt.ip.dst
            if src in ip_counts:
                ip_counts[src] += 1
            else:
                ip_counts[src] = 1
            if dst in ip_counts:
                ip_counts[dst] += 1
            else:
                ip_counts[dst] = 1
        except AttributeError:
            logger.info("Packet %d has no IP layer, skipping", i)
            continue  # Packet has no IP layer

    return ip_counts


def extract_domains(cap) -> set:
    """
    Extracts unique domain names from DNS packets in a given packet capture.
    Iterates over the provided packet capture object, inspects each packet for DNS queries,
    and collects the queried domain names into a set to ensure uniqueness.
    Args:
        cap (iterable): An iterable of packet objects, each potentially containing DNS information.
    Returns:
        set: A set of unique domain names (as strings) extracted from DNS query packets.
    """
    domains = {}
    for i, pkt in enumerate(cap):
        logger.info("Extracting domains from packet %d/%d", i, len(list(cap)))
        if "DNS" in pkt:
            try:
                query = pkt.dns.qry_name
                if query in domains:
                    domains[query] += 1
                else:
                    domains[query] = 1
            except AttributeError:
                continue
    return domains


def assemble_report(ips, domains, ip_info=None, rules=None) -> dict:
    """
    Assembles a report containing unique IPs, domains, and optional IP information.
    Args:
        ips (Iterable): A collection of unique IP addresses.
        domains (Iterable): A collection of unique domain names.
        ip_info (Optional[Any]): Additional information about the IPs (default is None).
        rules (Optional[dict]): IOC rules to apply for blacklisting (default is None).
    Returns:
        dict: A dictionary containing the report with the following keys:
            - "save_time": ISO formatted timestamp of report creation.
            - "unique_ips": List of unique IP addresses.
            - "unique_domains": List of unique domain names.
            - "ip_info": (Optional) Additional IP information if provided.
    """
    # TODO: include protocol of packets in the report somehow
    if rules == {}:
        rules = None

    report = {
        "save_time": datetime.now().isoformat(),
        "unique_ips": list(set(ips.keys())),
        "unique_domains": list(set(domains.keys())),
    }

    if ip_info is not None:
        report["ip_info"] = ip_info

    # TODO: Allow more flexible labels - e.g. wildcard matching on domains (*.example.com), CIDR for IPs (255.*.*.*), etc.
    if rules is not None and isinstance(rules, dict):
        if "ip_blacklist" in rules:
            report["blacklisted_ips"] = [
                ip for ip in set(ips.keys()) if ip in rules["ip_blacklist"]
            ]
        if "domain_blacklist" in rules:
            report["blacklisted_domains"] = [
                domain
                for domain in set(domains.keys())
                if domain in rules["domain_blacklist"]
            ]
        if "city_blacklist" in rules:
            report["blacklisted_cities"] = []
            if ip_info is not None:
                for info in ip_info:
                    if "city" in info and info["city"] in rules["city_blacklist"]:
                        report["blacklisted_cities"].append(info)

    return report


def load_rules(rule_file: str) -> dict:
    """
    Loads IOC rules from a JSON or YAML file.
    Args:
        rule_file (str): Path to the rules file.
    Returns:
        dict: The loaded rules as a dictionary.
    Raises:
        FileNotFoundError: If the specified rule_file does not exist.
        ValueError: If the file format is unsupported or if there are parsing errors.
        NotImplementedError: If YAML support is attempted.
    """
    if rule_file is None:
        return {}
    rule_file = os.path.abspath(rule_file)
    if not os.path.exists(rule_file):
        raise FileNotFoundError(f"Rules file {rule_file} does not exist")

    _, ext = os.path.splitext(rule_file)
    try:
        if ext.lower() == ".json":
            with open(rule_file, "r", encoding="utf-8") as f:
                rules = json.load(f)
        elif ext.lower() in [".yaml", ".yml"]:
            raise NotImplementedError("YAML support not implemented yet")
        else:
            raise ValueError(f"Unsupported file format. Expected JSON, but got {ext}.")
    except json.JSONDecodeError as e:
        logger.error("Error parsing rules file: %s", e)
        raise ValueError(f"Error parsing rules file: {e}") from e

    return rules


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
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=4)
    except IOError as e:
        logger.error("Error writing to file %s: %s", out_file, e)
    except TypeError as e:  # Catch JSON serialization errors
        logger.error("Error serializing report to JSON: %s", e)
    except Exception as e:  # Catch other potential file-related errors
        logger.error("An unexpected error occurred during file operation: %s", e)
        raise e


def analyze_file(in_file: str, out_file: str = None, rule_file: str = None) -> dict:
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
    logger.info("Loading pcap file %s", in_file)  # debugging
    cap = load_pcap(in_file)
    logger.info("Loaded pcap file %s", in_file)  # debugging

    return analyze(cap, out_file=out_file, rule_file=rule_file)


def analyze(cap, out_file: str = None, rule_file: str = None) -> dict:
    """
    Analyzes a pcap capture object to extract unique IP addresses and domains, gathers information about each IP,
    and generates a report. Optionally saves the report to a specified output file.
    Args:
        cap: The pcap capture object to analyze.
        out_file (str, optional): Path to save the generated report. If None, the report is not saved to disk.
    Returns:
        dict: The assembled report containing extracted IPs, domains, and IP information.
    """

    logger.info("Extracting IPs and domains")  # debugging
    ip_counts = extract_ips(cap)
    logger.info("Extracted %d unique IPs", len(set(ip_counts)))  # debugging

    logger.info("Extracting Domains")  # debugging
    domain_counts = extract_domains(cap)
    logger.info("Extracted %d unique domains", len(set(domain_counts)))  # debugging

    ip_info = [get_ip_info(ip_address=addr) for addr in set(ip_counts)]

    report = assemble_report(
        ip_counts, domain_counts, ip_info=ip_info, rules=load_rules(rule_file)
    )

    if out_file is not None:
        save_report(report, out_file=out_file)
        logger.info("Report saved to %s", out_file)

    return report
