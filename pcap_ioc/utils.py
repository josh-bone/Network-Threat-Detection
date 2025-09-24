import pyshark
import json
import argparse
import requests

def get_ip_info(ip_address:str) -> dict | Exception:
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

def make_pcap(file_path):
    # TODO Use pyshark to capture packets and put them in file_path
    pass

def load_pcap(file_path):
    cap = pyshark.FileCapture(file_path)
    return cap

def extract_ips(cap):
    ips = set()
    for pkt in cap:
        try:
            src = pkt.ip.src
            dst = pkt.ip.dst
            ips.add(src)
            ips.add(dst)
        except AttributeError:
            continue  # Packet has no IP layer
    return ips

def extract_domains(cap):
    domains = set()
    for pkt in cap:
        if 'DNS' in pkt:
            try:
                query = pkt.dns.qry_name
                domains.add(query)
            except AttributeError:
                continue
    return domains

def save_report(ips, domains, out_file):
    report = {
        'unique_ips': list(ips),
        'unique_domains': list(domains)
    }
    with open(out_file, 'w') as f:
        json.dump(report, f, indent=4)
        
def run(in_file, out_file='report.json'):
    # TODO: Call API to check for suspicious IPs
    cap = load_pcap(in_file)
    
    ips = extract_ips(cap)
    domains = extract_domains(cap)
    
    save_report(ips, domains, out_file)
    
    print(f"Found {len(ips)} unique IPs and {len(domains)} unique domains.")
