"""
Command-line interface for the parse-pcap tool.
"""

# Standard imports
import argparse
import os
import logging
import json

# Local imports
from parse_pcap.utils import capture_packets, analyze_file
from parse_pcap.visualization import visualize_all

logger = logging.getLogger(__name__)


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

    parser = argparse.ArgumentParser(description="Analyze PCAPs for IOCs")
    parser.add_argument(
        "command",
        choices=["capture", "analyze", "visualize"],
        help="Command to execute",
    )
    parser.add_argument(
        "-p",
        "--pcap_file",
        help="Path to the PCAP file to analyze. If unspecified, a live capture will be taken",
        type=os.path.abspath,
        required=False,
    )
    parser.add_argument(
        "-r", "--rules", help="Path to IOC rules file (JSON/YAML)", required=False
    )
    parser.add_argument(
        "--report_file",
        required=False,
        type=os.path.abspath,
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
    parser.add_argument(
        "-v", "--visualize", action="store_true", help="Visualize results in terminal"
    )
    parser.add_argument(
        "-l",
        "--log_level",
        type=str,
        default="ERROR",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Set the logging level (default: ERROR)",
    )
    args = parser.parse_args()

    if args.log_level == "DEBUG":
        logging.basicConfig(level=logging.DEBUG)
    elif args.log_level == "INFO":
        logging.basicConfig(level=logging.INFO)
    elif args.log_level == "WARNING":
        logging.basicConfig(level=logging.WARNING)
    elif args.log_level == "ERROR":
        logging.basicConfig(level=logging.ERROR)
    elif args.log_level == "CRITICAL":
        logging.basicConfig(level=logging.CRITICAL)

    logger.info("args.report_file: %s", args.report_file)  # debugging
    logger.info("args.pcap_file: %s", args.pcap_file)  # debugging

    if args.command == "capture" or (
        args.pcap_file is None and args.command == "analyze"
    ):
        _ = capture_packets(
            output_filename=args.pcap_file,
            interface=args.capture_interface,
            duration=args.capture_duration,
        )
    elif args.command == "analyze":
        assert os.path.exists(
            args.pcap_file
        ), f"PCAP file {args.pcap_file} does not exist"  # At this point the file must exist
        logger.info("Analyzing %s with rules in %s", args.pcap_file, args.rules)
        report = analyze_file(
            args.pcap_file, out_file=args.report_file, rule_file=args.rules
        )
        if args.visualize:
            visualize_all(report)
    elif args.command == "visualize":
        assert (
            args.report_file is not None
        ), "Please specify a report file with --report_file"
        assert os.path.exists(
            args.report_file
        ), f"Report file {args.report_file} does not exist"

        # Load the report from the specified JSON file
        try:
            with open(args.report_file, "r", encoding="utf-8") as f:
                report = json.load(f)
        except json.JSONDecodeError as e:
            logger.error("Failed to parse report file %s:\n%s", args.report_file, e)
            return
        except FileNotFoundError as e:
            logger.error("Report file not found: %s:\n%s", args.report_file, e)
            return

        visualize_all(report)
