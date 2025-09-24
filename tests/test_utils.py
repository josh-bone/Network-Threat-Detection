import pytest
import json
from unittest import mock
from pcap_ioc import utils

class DummyPkt:
    def __init__(self, src=None, dst=None, dns_query=None, has_ip=True, has_dns=False):
        self.layers = []
        if has_ip:
            self.ip = mock.Mock()
            self.ip.src = src
            self.ip.dst = dst
        if has_dns:
            self.dns = mock.Mock()
            self.dns.qry_name = dns_query
            self.layers.append('DNS')

    def __contains__(self, item):
        return item == 'DNS' and hasattr(self, 'dns')

def test_extract_ips_basic():
    pkts = [
        DummyPkt(src='1.1.1.1', dst='2.2.2.2'),
        DummyPkt(src='3.3.3.3', dst='4.4.4.4'),
        DummyPkt(has_ip=False)  # Should be skipped
    ]
    result = utils.extract_ips(pkts)
    assert result == {'1.1.1.1', '2.2.2.2', '3.3.3.3', '4.4.4.4'}

def test_extract_domains_basic():
    pkts = [
        DummyPkt(has_ip=True, has_dns=True, dns_query='example.com'),
        DummyPkt(has_ip=True, has_dns=True, dns_query='test.com'),
        DummyPkt(has_ip=True, has_dns=False)
    ]
    result = utils.extract_domains(pkts)
    assert result == {'example.com', 'test.com'}

def test_extract_domains_handles_attribute_error():
    pkt = DummyPkt(has_ip=True, has_dns=True)
    del pkt.dns.qry_name  # Remove attribute to trigger AttributeError
    pkts = [pkt]
    result = utils.extract_domains(pkts)
    assert result == set()

def test_save_report(tmp_path):
    ips = {'1.1.1.1', '2.2.2.2'}
    domains = {'example.com'}
    out_file = tmp_path / "report.json"
    utils.save_report(ips, domains, str(out_file))
    with open(out_file) as f:
        data = json.load(f)
    assert set(data['unique_ips']) == ips
    assert set(data['unique_domains']) == domains

@mock.patch("pcap_ioc.utils.load_pcap")
@mock.patch("pcap_ioc.utils.save_report")
def test_run_calls_all_functions(mock_save_report, mock_load_pcap):
    fake_cap = [DummyPkt(src='1.1.1.1', dst='2.2.2.2', has_ip=True, has_dns=True, dns_query='abc.com')]
    mock_load_pcap.return_value = fake_cap
    utils.run("fakefile.pcap", "output.json")
    mock_load_pcap.assert_called_once_with("fakefile.pcap")
    mock_save_report.assert_called_once()
    args, kwargs = mock_save_report.call_args
    assert '1.1.1.1' in args[0]
    assert '2.2.2.2' in args[0]
    assert 'abc.com' in args[1]
    assert args[2] == "output.json"

@mock.patch("pyshark.FileCapture")
def test_load_pcap_calls_pyshark(mock_file_capture):
    utils.load_pcap("somefile.pcap")
    mock_file_capture.assert_called_once_with("somefile.pcap")