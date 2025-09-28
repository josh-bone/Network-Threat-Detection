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

import logging

logger = logging.getLogger(__name__)


def visualize_all(report):
    """
    Displays allpossible visualizations in the module.
    Args:
        report (dict): The report data containing information about violations to be visualized.
    Returns:
        None
    """
    show_violations(report)


def show_violations(report):
    """
    Displays rule violations from a given report dictionary.
    This function prints information about blacklisted cities, IPs, and domains found in the report.
    For each blacklisted city, it counts and displays the number of IP addresses associated with that city.
    It also logs findings using the logger.
    Args:
        report (dict): A dictionary containing analysis results, expected to have keys such as
            'blacklisted_cities', 'blacklisted_ips', 'blacklisted_domains', and 'ip_info'.
    Returns:
        None
    """

    print("\n=== Rule Violations ===")

    if "blacklisted_cities" in report and len(report["blacklisted_cities"]) > 0:
        print("IP addresses from blacklisted cities")
        logger.info("Blacklisted cities found")
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
        logger.info("Blacklisted IPs found")
        print("\nBlacklisted IPs found:")
        for ip in report["blacklisted_ips"]:
            print(f"  {ip}")

    if "blacklisted_domains" in report and len(report["blacklisted_domains"]) > 0:
        logger.info("Blacklisted Domains found")
        print("\nBlacklisted Domains found:")
        for domain in report["blacklisted_domains"]:
            print(f"  {domain}")
