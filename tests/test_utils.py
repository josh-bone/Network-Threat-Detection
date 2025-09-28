"""
Unit tests for the utility functions in the `parse_pcap.utils` module.

This test suite covers:
- Extraction of IP addresses and domain names from packet-like objects.
- Handling of packets with missing or malformed attributes.
- Saving and loading of analysis reports in JSON format.
- Error handling for missing PCAP files.
- Integration of main analysis workflow, ensuring all core functions are called.
- Interaction with external dependencies such as `pyshark.FileCapture`.

Classes:
    DummyPkt: A mock packet class used to simulate network packets with optional IP and DNS layers.

Test Functions:
    test_get_ip_info: Tests retrieval of IP information.
    test_extract_ips_basic: Tests extraction of IP addresses from packets.
    test_extract_domains_basic: Tests extraction of domain names from packets.
    test_extract_domains_handles_attribute_error: Ensures robustness when DNS query attribute is missing.
    test_save_report: Tests saving of analysis results to a JSON file.
    test_load_pcap_no_file: Ensures FileNotFoundError is raised for missing PCAP files.
    test_run_calls_all_functions: Verifies the main analysis function calls all necessary utilities.
    test_capture_packets: Placeholder for future packet capture tests.
    test_load_pcap_calls_pyshark: Ensures PCAP loading uses pyshark's FileCapture.

Dependencies:
    - pytest
    - unittest.mock
    - json
    - parse_pcap.utils
"""

# Standard imports
import json
from unittest import mock
import random

# Third-party imports
import pytest

# Local imports
from parse_pcap import utils


class DummyPkt:
    """
    A dummy packet class for testing purposes, simulating network packet layers.
    Attributes:
        ip (mock.Mock): Mocked IP layer with 'src' and 'dst' attributes if 'has_ip' is True.
        dns (mock.Mock): Mocked DNS layer with 'qry_name' attribute if 'has_dns' is True.
        layers (list): List of present protocol layers as strings.
    Args:
        src (str, optional): Source IP address for the IP layer.
        dst (str, optional): Destination IP address for the IP layer.
        dns_query (str, optional): DNS query name for the DNS layer.
        has_ip (bool, optional): Whether to include an IP layer. Defaults to True.
        has_dns (bool, optional): Whether to include a DNS layer. Defaults to False.
    Methods:
        __contains__(item): Returns True if 'item' is "DNS" and the packet has a DNS layer.
    """

    def __init__(self, src=None, dst=None, dns_query=None, has_ip=True, has_dns=False):
        """
        Initialize the mock packet object with optional IP and DNS layers.

        Args:
            src (str, optional): Source IP address. Defaults to None.
            dst (str, optional): Destination IP address. Defaults to None.
            dns_query (str, optional): DNS query name. Defaults to None.
            has_ip (bool, optional): Whether to include an IP layer. Defaults to True.
            has_dns (bool, optional): Whether to include a DNS layer. Defaults to False.

        Attributes:
            layers (list): List of protocol layers present in the packet.
            ip (mock.Mock): Mock object representing the IP layer (if has_ip is True).
            dns (mock.Mock): Mock object representing the DNS layer (if has_dns is True).
        """
        self.layers = []
        if has_ip:
            self.ip = mock.Mock()
            self.ip.src = src
            self.ip.dst = dst
        if has_dns:
            self.dns = mock.Mock()
            self.dns.qry_name = dns_query
            self.layers.append("DNS")

    def __contains__(self, item):
        return item == "DNS" and hasattr(self, "dns")


def random_ip() -> str:
    """
    Generates a random IPv4 address in dotted-decimal notation.

    Returns:
        str: IP address
    """
    ip = ".".join(str(random.randint(0, 255)) for _ in range(4))
    return ip


def test_get_ip_info():
    """
    Test the `get_ip_info` function from the `utils` module.
    This test verifies that:
    - The function returns a dictionary when provided with a valid IP address.
    - The returned dictionary contains the correct IP address under the "ip" key.
    Returns:
        None
    """

    ip = random_ip()
    result = utils.get_ip_info(ip)
    assert isinstance(result, dict)
    assert result.get("ip") == ip


def test_extract_ips_basic():
    """
    Test the basic functionality of the extract_ips function.
    This test verifies that extract_ips correctly extracts all unique source and destination IP addresses
    from a list of packet-like objects, while skipping packets that do not contain IP information.
    Scenarios covered:
    - Packets with valid source and destination IPs are included in the result.
    - Packets without IP information (e.g., has_ip=False) are ignored.
    - The result is a set containing all unique IP addresses found.
    """
    random_ips = [random_ip() for _ in range(4)]

    pkts = [
        DummyPkt(src=random_ips[0], dst=random_ips[1]),
        DummyPkt(src=random_ips[2], dst=random_ips[3]),
        DummyPkt(has_ip=False),  # Should be skipped
    ]
    result = utils.extract_ips(pkts)
    assert result == set(random_ips)


def test_extract_domains_basic():
    """
    Test that `extract_domains` correctly extracts unique domain names from a list of packets.
    This test creates a list of dummy packet objects, some containing DNS queries and some not.
    It verifies that the function returns a set of all unique domain names found in the DNS queries,
    ignoring packets without DNS information.
    """

    pkts = [
        DummyPkt(has_ip=True, has_dns=True, dns_query="example.com"),
        DummyPkt(has_ip=True, has_dns=True, dns_query="test.com"),
        DummyPkt(has_ip=True, has_dns=False),
    ]
    result = utils.extract_domains(pkts)
    assert result == {"example.com", "test.com"}


def test_extract_domains_handles_attribute_error():
    """
    Test that extract_domains returns an empty set when a packet's DNS query name attribute is missing,
    ensuring it gracefully handles AttributeError exceptions.
    """

    pkt = DummyPkt(has_ip=True, has_dns=True)
    del pkt.dns.qry_name  # Remove attribute to trigger AttributeError
    pkts = [pkt]
    result = utils.extract_domains(pkts)
    assert result == set()


def test_save_report(tmp_path):
    """
    Test the `save_report` function to ensure it correctly writes the provided sets of IPs and domains
    to a JSON file. The test verifies that the output file contains the expected unique IPs and domains.
    """

    ips = {random_ip() for _ in range(2)}
    domains = {"example.com"}
    out_file = tmp_path / "report.json"
    report = utils.assemble_report(ips, domains)
    utils.save_report(report, out_file=str(out_file))
    with open(out_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert set(data["unique_ips"]) == ips
    assert set(data["unique_domains"]) == domains


def test_capture_packets():
    """
    Test the capture_packets function to ensure it checks its input parameters correctly.
    """

    with pytest.raises(ValueError):
        _ = utils.capture_packets(
            output_filename=None, duration=-1
        )  # Invalid interface should raise ValueError


def test_load_pcap_no_file():
    """
    Test that utils.load_pcap raises a FileNotFoundError when attempting to load a non-existent pcap file.
    """

    with pytest.raises(FileNotFoundError):
        utils.load_pcap("nonexistent.pcap")


@mock.patch("parse_pcap.utils.load_pcap")
@mock.patch("parse_pcap.utils.save_report")
def test_analyze_file(mock_load_pcap):
    """
    Test the analyze_file function to ensure it orchestrates the workflow correctly:
    - It should call load_pcap with the input file.
    - It should call analyze with the returned capture object.
    - It should pass out_file and rule_file to analyze.
    - It should return the result from analyze.
    """
    dummy_cap = mock.Mock()
    mock_load_pcap.return_value = dummy_cap

    with mock.patch("parse_pcap.utils.analyze") as mock_analyze:
        mock_analyze.return_value = {"result": "ok"}
        result = utils.analyze_file(
            "input.pcap", out_file="output.json", rule_file="rules.json"
        )
        mock_load_pcap.assert_called_once_with("input.pcap")
        mock_analyze.assert_called_once_with(
            dummy_cap, out_file="output.json", rule_file="rules.json"
        )
        assert result == {"result": "ok"}
