import argparse
from pcap_ioc.utils import run

def main():
    parser = argparse.ArgumentParser(description="Analyze PCAPs for IOCs")
    parser.add_argument("pcap_file", help="Path to the PCAP file to analyze")
    parser.add_argument("--rules", help="Path to IOC rules file (JSON/YAML)", required=False)
    parser.add_argument('--out_file', required=False, type=str, default='report.json', help='Output report file path')

    args = parser.parse_args()

    print(f"Analyzing {args.pcap_file} with rules {args.rules}")
    run(args.pcap_file, args.out_file)
