import argparse
import os
from pcap_ioc.utils import capture_packets, analyze_file
import logging

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


def main():
    print(f"PCAP IOC Analyzer v0.1")  # Mostly for debugging :)
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
    )  # TODO: implement rules file
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
        capture = capture_packets(
            output_filename=pcap_file,
            interface=args.capture_interface,
            duration=args.capture_duration,
        )
        pcap_file = capture._output_file
        print(f"Capture saved to {pcap_file}")  # debugging
        logger.info(f"Capture saved to {pcap_file}")
    elif args.command == "analyze":
        assert os.path.exists(
            pcap_file
        ), f"PCAP file {pcap_file} does not exist"  # At this point the file must exist
        print(f"Analyzing {pcap_file} with rules {args.rules}")
        analyze_file(pcap_file, out_file=args.out_file)
