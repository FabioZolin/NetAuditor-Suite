# ICMPAuditor

**A lightweight, memory-efficient PCAP analyzer designed for Blue Teams and Threat Hunters to detect ICMP tunneling, C2 beaconing, and data exfiltration.**

ICMPAuditor parses network captures (`.pcap`) streaming them packet-by-packet. It hunts for malicious actors abusing the ICMP protocol to bypass firewall restrictions, without eating up your system's RAM.

It has been tested with capture files from **Active Countermeasures** showing very little false positives and identifying all tunneling instances running on stock configuration

## Key Features

* **Dual Entropy Analysis**: Calculates both classical Shannon and Delta (differential) to ignore standard traffic and catch malicious payloads.
* **Symmetry check**: Tracks outbound Requests and matches them with inbound Replies to detect asymmetric C2 communications (e.g., when a 10-byte ping triggers a 500-byte command response).
* **Volumetric Beaconing Detection**: Tracks packet counts per IP to spot noisy C2 beacons and flooding.
* **Diagnostic Channel Evasion**: Checks the payload of diagnostic packets (e.g., *Destination Unreachable*) to catch advanced malware hiding data inside fake router errors.
* **Memory Efficient**: Uses Scapy's `PcapReader` to stream packets. Analyzes multi-gigabyte PCAPs without crashing.

## Setup & Requirements

Since this tool is part of the **NetAuditor Suite**, it relies on the global requirements of the project.

**1. Ensure you have installed the global requirements from the root directory:**
> pip install -r ../requirements.txt

**2. Navigate to this tool's folder and run it:**
> cd ICMPAuditor
> python ICMPAuditor.py -f capture.pcap

## Usage

### Command Line Options

| Flag | Long Name | Description | Default |
| :--- | :--- | :--- | :--- |
| `-f` | `--file` | Path to the `.pcap` file to analyze (Required). | - |
| `-s` | `--size` | Max allowed ICMP payload size in bytes before flagging. | `64` |
| `-et` | `--entropy`| Minimum Shannon entropy score before flagging. | `4.0` |
| `-dt` | `--delta` | Minimum Delta entropy score before flagging. | `2.5` |
| `-vl` | `--volume` | Max ICMP packets per IP before flagging beaconing/flooding. | `1000` |
| `-nt` | `--no_types`| Turns off flagging of IPs using unusual or deprecated ICMP types. | `False` |
| `-v` | `--verbose` | Enable verbose mode (displays individual alerts and snippets). | `False` |
| `-vv`| `--very_verbose`| Enable very verbose mode (displays ALL traffic, including normal).| `False` |

### Whitelisting
Specifing a whitelist can be very helpful to prevent many false positives and noise, the .txt file has to contain one ip per line like this:
```txt
192.168.3.1
85.93.230.98
8.8.8.8
```

### Usage Examples
**Basic Analysis:**
Scans the file using default thresholds.
```bash
python ICMPAuditor.py -f capture.pcap
```

**Verbose Mode:**
Displays individual alerts, anomalies, and shows a safe string snippet of the malicious payload.
```bash
python ICMPAuditor.py -f capture.pcap -v
```

**Custom Tuning:**
Increases the allowed payload size to 100 bytes, raises the entropy thresholds, and silences unusual ICMP types alerts.
```bash
python ICMPAuditor.py -f capture.pcap -s 100 -et 4.5 -dt 3.0 -nt -v
```

---

### Why Delta Entropy?
I'd like to add a little explanation on why i chose to use delta entropy instead of the regular one.
Standard ping commands on Windows or Linux often pad their payloads with repeating alphabets (e.g., abcdefghijklmnopqrstuvw...). Classical Shannon entropy might flag a long repeating alphabet as somewhat anomalous if the threshold is too strict. 

ICMPAuditor uses **Differential (Delta) Entropy** to measure the mathematical "jumps" between consecutive bytes. This effectively zeroes out the entropy of sequential or highly repetitive OS pings, silencing false positives while accurately catching true encryption, compression, or binary data injected by attackers.
