# NetScan

[![Python Version](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg)](#)

NetScan is a Python-based network port scanner security tool that helps security engineers and system administrators identify exposed services, assess risk severity, and produce actionable scan reports. It combines TCP/UDP scanning, service fingerprinting, optional OS detection, and CVE enrichment to support fast triage and defensive security assessments on authorised infrastructure.

## Features

- TCP and UDP port scanning
- Service and version detection
- OS fingerprinting
- Risk assessment with severity levels (Critical, High, Medium, Low)
- CVE lookups via the NIST NVD API
- JSON and HTML report generation
- Colour-coded terminal summary for quick triage

## Requirements

- Python 3.9+
- Nmap 7.x
- Pip dependencies from `requirements.txt`:

```bash
certifi==2026.2.25
charset-normalizer==3.4.7
idna==3.11
iniconfig==2.3.0
Jinja2==3.1.6
MarkupSafe==3.0.3
packaging==26.1
pluggy==1.6.0
Pygments==2.20.0
pytest==9.0.3
python-nmap==0.7.1
requests==2.33.1
urllib3==2.6.3
```

## Installation

```bash
git clone https://github.com/ApacheSBC/netscan.git
cd netscan
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage

### Basic scan

```bash
sudo python run.py 192.168.1.1 --ports 1-1024
```

### With UDP

```bash
sudo python run.py 192.168.1.1 --ports 1-1024 --udp
```

### With OS detection

```bash
sudo python run.py 192.168.1.1 --ports 1-1024 --os
```

### With CVE lookup

```bash
sudo python run.py 192.168.1.1 --ports 1-1024 --cve
```

### Full scan

```bash
sudo python run.py 192.168.1.1 --ports 1-1024 --udp --os --cve
```

### Skip reports

```bash
sudo python run.py 192.168.1.1 --no-report
```

## Sample Output

NetScan generates a professional HTML report that includes a high-level risk summary and detailed findings. The summary section displays risk cards for Critical, High, Medium, and Low findings, while the findings table is colour-coded by severity and includes host, port, protocol, service, product/version, risk reason, and related CVE IDs when enrichment is enabled.

## Project Structure

```text
netscan/
├── conftest.py
├── requirements.txt
├── run.py
├── README.md
├── netscan/
│   ├── cli.py
│   ├── scanner.py
│   ├── risk.py
│   ├── cve.py
│   └── report.py
└── tests/
    └── test_risk.py
```

## Legal Disclaimer

This tool is provided for authorised security testing only. Unauthorized scanning of systems, networks, or services may be illegal and can violate organisational policy and applicable law. Only scan systems you own or systems for which you have explicit written permission to test.

## Built With

- Python
- Nmap
- python-nmap
- NIST NVD API

## Author

- ApacheSBC - [https://github.com/ApacheSBC](https://github.com/ApacheSBC)
