"""_summary_
This module provides functions for visualizing and summarizing network packet data.
Functions:
    summarize_protocols(packets):
        Prints a summary of protocol distribution among the provided packets, displaying a bar chart for each protocol.
    top_ips(packets, n=10):
        Prints the top n source IP addresses by occurrence in the provided packets.
    show_violations(packets, rules):
        Prints packets that violate specified rules, such as blacklisted IPs or cities.
"""


def visualize_all(report):
    show_violations(report)

def show_violations(report):
    print("\n=== Rule Violations ===")
    
    if "blacklisted_cities" in report and len(report["blacklisted_cities"]) > 0:
        print(f"IP addresses from blacklisted cities")
        for city in report["blacklisted_cities"]:
            # There's probably a more efficient way...
            count = len(
                [
                    city.lower()
                    for info in report["ip_info"]
                    if info.get("city").lower() == city.lower()
                ]
            )
            print(f"  {city}\t{count}")
            
    if "blacklisted_ips" in report and len(report["blacklisted_ips"]) > 0:
        print(f"\nBlacklisted IPs found:")
        for ip in report["blacklisted_ips"]:
            print(f"  {ip}")

    if "blacklisted_domains" in report and len(report["blacklisted_domains"]) > 0:
        print(f"\nBlacklisted Domains found:")
        for domain in report["blacklisted_domains"]:
            print(f"  {domain}")