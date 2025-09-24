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

```
pcap-ioc /path/to/packet_capture.pcap
```