# NetAuditor Suite

**A collection of PCAP analysis tools designed to detect data exfiltration, C2 beaconing, and tunneling through protocol-specific analysis.**

The NetAuditor Suite provides specialized, memory-efficient scripts to analyze network captures (`.pcap`) protocol by protocol. These tools use Scapy and Pyshark libraries to parse thousands of packets of traffic, apply statistical models, and highlight anomalous behaviors typical of advanced persistent threats (APTs) and modern malware.

Where possible the scripts perform DPI in search of Indicators of Compromise, such as high entropy DNS queries, asymmetric PING payloads and domains generated via Domain Generation Algorithms.

## The Toolkit

Currently, the suite includes the following specialized auditors. **Click on each tool's name to read its specific documentation and usage guide.**

| Tool | Target Protocol | Detection Capabilities |
| :--- | :--- | :--- |
| [**TLSAuditor**](./TLSAuditor) | TLS | C2 Beaconing, SNI anomalies, TLS Light fingerprinting. |
| [**DNSAuditor**](./DNSAuditor) | DNS | C2 Beaconing and Data exfiltration, High-volume TXT/NULL queries, High entropy queries. |
| [**ICMPAuditor**](./ICMPAuditor) | ICMP | C2 Beaconing and Data exfiltration, Payload entropy analysis, Deprecated/not existing message type usage. |

## Global Installation

The suite is designed to be highly portable with minimal dependencies.

**1. Clone the repository:**
```bash
git clone https://github.com/YOUR_USERNAME/NetAuditor-Suite.git
cd NetAuditor-Suite
```
**2. Create a virtual environment (Optional):**
```bash
python -m venv venv
source venv/bin/activate  # On Windows use: venv\Scripts\activate
```
**3. Install the global requirements:**
```bash
pip install -r requirements.txt
```
*(This will install the required core libraries like scapy and colorama for all the tools in the suite).*

---

### Current Development
Currently being submitted as an extracurricular project for the university course "Reti di Calcolatori" (Computer Networks)
