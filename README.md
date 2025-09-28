# Parse_pcap

Parse_pcap is a security tool designed to analyze packet capture files (pcap) for indicators of compromise (IOCs). It helps security professionals quickly identify suspicious activity within network traffic.

## Features

- Analyze existing pcap files for IOCs
- Capture live network traffic for analysis
- Output results in JSON format
- Usable as both a command-line tool and a Python library

## Installation

This is published on PyPi, so you can run the following to install:

```bash
pip install parse-pcap
```

> **Note:** The package will be available on PyPI soon.

## Usage

### Command-Line Interface

**Analyze an existing pcap file:**

```bash
parse_pcap analyze -p /path/to/packet_capture.pcap -r /path/to/results.json
```

**Capture live network traffic:**

```bash
parse_pcap capture -o /path/to/capture.pcapng -i capture_interface -t 2
```

**Visualize an existing report:**
```bash
parse_pcap visualize --report_file /path/to/results.json
```

### Python Library

You can also use Parse_pcap as a Python library:

```python
from parse_pcap.utils import load_pcap, analyze

cap = load_pcap(in_file)
results = analyze(cap, out_file=out_file)
```