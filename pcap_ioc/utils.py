import pyshark
import json
import argparse

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
    cap = load_pcap(in_file)
    
    ips = extract_ips(cap)
    domains = extract_domains(cap)
    
    save_report(ips, domains, out_file)
    
    print(f"Found {len(ips)} unique IPs and {len(domains)} unique domains.")
