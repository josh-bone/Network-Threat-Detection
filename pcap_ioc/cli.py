"""
Command-line interface for the pcap_ioc tool.
"""

# Standard imports
import argparse
import os
import logging

# Local imports
from pcap_ioc.utils import capture_packets, analyze_file

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


def main():
    """
    Main entry point for the PCAP IOC Analyzer CLI.
    Parses command-line arguments to either capture network packets or analyze a given PCAP file for Indicators of Compromise (IOCs).
    Supports specifying a PCAP file, IOC rules file, output report path, network interface, and capture duration.
    Commands:
        - capture: Captures live network traffic and saves it to a PCAP file.
        - analyze: Analyzes a specified PCAP file for IOCs.
    Arguments:
        command (str): The command to execute ("capture" or "analyze").
        -p, --pcap_file (str, optional): Path to the PCAP file to analyze. If not provided, a live capture is performed.
        -r, --rules (str, optional): Path to IOC rules file (JSON/YAML). (Not yet implemented)
        -o, --out_file (str, optional): Output report file path. Defaults to "report.json".
        -i, --capture_interface (str, optional): Network interface to capture on. Defaults to "en0".
        -t, --capture_duration (int, optional): Duration of capture in seconds. Defaults to 10.
    Raises:
        AssertionError: If the specified PCAP file does not exist when analyzing.
    Side Effects:
        - Captures network traffic and saves to a file.
        - Analyzes PCAP files and generates a report.
        - Prints status messages and logs events.
    """

    print("PCAP IOC Analyzer v0.1")  # Mostly for debugging :)
    parser = argparse.ArgumentParser(description="Analyze PCAPs for IOCs")
    parser.add_argument(
        "command", choices=["capture", "analyze"], help="Command to execute"
    )
    parser.add_argument(
        "-p",
        "--pcap_file",
        help="Path to the PCAP file to analyze. If unspecified, a live capture will be taken",
        required=False,
    )
    parser.add_argument(
        "-r", "--rules", help="Path to IOC rules file (JSON/YAML)", required=False
    )
    parser.add_argument(
        "-o",
        "--out_file",
        required=False,
        type=str,
        default="report.json",
        help="Output report file path",
    )
    parser.add_argument(
        "-i",
        "--capture_interface",
        required=False,
        type=str,
        default="en0",
        help="Network interface to capture on (default: en0)",
    )
    parser.add_argument(
        "-t",
        "--capture_duration",
        required=False,
        type=int,
        default=10,
        help="Duration of capture in seconds (default: 10)",
    )
    args = parser.parse_args()

    pcap_file = args.pcap_file

    if args.command == "capture" or (pcap_file is None and args.command == "analyze"):
        _ = capture_packets(
            output_filename=args.out_file,
            interface=args.capture_interface,
            duration=args.capture_duration,
        )
    elif args.command == "analyze":
        assert os.path.exists(
            pcap_file
        ), f"PCAP file {pcap_file} does not exist"  # At this point the file must exist
        logger.info("Analyzing %s with rules in %s", pcap_file, args.rules)
        analyze_file(pcap_file, out_file=args.out_file, rule_file=args.rules)
