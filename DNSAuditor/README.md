# DNS Tunneling & Exfiltration Auditor (v2.0)

A lightweight PCAP analyzing tool designed to audit DNS traffic in .pcap capture files and find potential data exfiltration or C2 packets, identifying potentially compromised hosts.

This script performs packet inspection on both outbound queries (`DNSQR`) and inbound C2 responses (`DNSRR`), identifying malicious behaviour.

## Features

DNSAuditor can:
- **Analyze PCAP files offline** without exhausting system RAM even with sizable PCAP files, thanks to sequential packet processing.
- **Calculate Shannon Entropy** to automatically detect encrypted or encoded data hidden in subdomains, the entropy is automatically adjusted based on the detected alphabet (Hex, Base32, Base64/ Regular Text) .
- **Detect Domain Anomalies** such as excessively long query lengths or abnormal subdomain counts indicating possible data exfiltration.
- **Anomalies Report** the script offers a detailed report on possible internal host compromission and which domains show suspicious behaviour.
- **Filter Noise** via tiered verbosity levels (`-v` for critical alerts, `-vv` for all warnings).
- **C2 Payload Extraction:** Intercepts and decodes TXT and NULL record responses, highlighting the inbound binary/text payloads sent by the attacker.

## Setup & Requirements

Since this tool is part of the **NetAuditor Suite**, it relies on the global requirements of the project.

**1. Ensure you have installed the global requirements from the root directory:**
> pip install -r ../requirements.txt

**2. Navigate to this tool's folder and run it:**
> cd DNSAuditor
> python DNSAuditor.py -f capture.pcap

## Usage

Use the `-h` flag to display all available options and thresholds while in the terminal.

### Arguments List
| Flag | Name | Description | Default |
| :--- | :--- | :--- | :--- |
| `-f` | `--file` | **(Required)** Path to the `.pcap` file | - |
| `-dl` | `--domain_length` | Max allowed domain length before flagging | `30` |
| `-et` | `--entropy_threshold` | Minimum Shannon entropy score before flagging | `4.0` |
| `-sn` | `--subdomain_number`| Max number of subdomains before flagging | `5` |
| `-v` | `--verbose` | Shows standard warnings and suspicious records | `False` |
| `-vv`| `--very_verbose` | Shows everything (including presumed legit TXT) | `False` |
| `-t` | `--txt` | Displays all TXT DNS requests | `False` |
| `-n` | `--null` | Displays all NULL DNS requests (Highly suspicious) | `False` |
| `-c` | `--cname` | Displays all CNAME DNS requests | `False` |
| `-wl` | `--whitelist` | Path to a .txt file containing trusted root domains | - |

### Usage Examples
Run the script providing a `.pcap` or `.pcapng` file. 

#### Basic Analysis (Fast Triage)
Generates a statistical report and prints only High Entropy / NULL record alerts.
```bash 
python DNSAuditor.py -f suspicious_traffic.pcap
```

#### Deep Dive (Verbose Mode)
Prints all warnings (long domains, many subdomains, CNAME/TXT requests) and suspicious inbound C2 TXT formats.
```bash
python DNSAuditor.py -f suspicious_traffic.pcap -v
```

#### Custom Thresholds
If you are analyzing an environment with specific noise patterns, you can tweak the detection engine:
```bash
python DNSAuditor.py -f suspicious_traffic.pcap -dl 40 -et 4.5 -sn 6
```

### Whitelisting
Specifing a whitelist is fundamental to avoid many false positives and noise, the .txt file has to contain one root domain per line like this:
```txt
google.com
microsoft.com
amazon.com
```



## Built With
* Python 3
* [Scapy](https://scapy.net/) - Packet manipulation program & library
* [Colorama](https://pypi.org/project/colorama/) - Cross-platform colored terminal text
* [tldextract](https://pypi.org/project/tldextract/) - Accurate TLD separation for smart whitelisting and analysis
