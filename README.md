# IOC Detector

This is a security tool which takes a packet capture and analyzes it for indicators of compromise (IOC).

# How to Install

This is currently only available on testpypi, so you need to install with:
```
pip install -i https://test.pypi.org/simple/ \                       
    --extra-index-url https://pypi.org/simple \
pcap_ioc==0.1.3
```

Soon it will be published through pip.

# How to Use

## Command Line Usage

Analyze an existing file:
```
pcap-ioc analyze -p /path/to/packet_capture.pcap -o /path/to/results.json
```

Take a live packet capture:
```
pcap-ioc capture -o /path/to/capture.pcapng -i capture_interface
```

## Library Usage

Analyze an existing file:

```
from pcap_ioc.utils import load_pcap,analyze

cap = load_pcap(in_file)
results = analyze(cap)
```