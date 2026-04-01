# NetAuditor Suite

**A collection of PCAP analysis tools designed to detect data exfiltration, C2 beaconing, and tunneling through protocol-specific analysis.**

The NetAuditor Suite provides specialized, memory-efficient scripts to analyze network captures (`.pcap`) protocol by protocol. These tools use Scapy and Pyshark libraries to parse thousands of packets of traffic, apply statistical models, and highlight anomalous behaviors typical of advanced persistent threats (APTs) and modern malware.

## The Toolkit

Currently, the suite includes the following specialized auditors. **Click on each tool's name to read its specific documentation and usage guide.**

| Tool | Target Protocol | Key Capabilities |
| :--- | :--- | :--- |
| [**ICMPAuditor**](./ICMPAuditor) | ICMP | Payload asymmetry (RFC 792), Entropy analysis, C2 Beaconing, Covert channels. |
| [**DNSAuditor**](./DNSAuditor) | DNS | DNS Tunneling, DGA (Domain Generation Algorithms), High-volume TXT/A queries. |
| [**HTTPSAuditor**](./TLSAuditor) | HTTPS / TLS | Behavioral beaconing (Jitter/Delta time), SNI anomalies, TLS fingerprinting. |

## Global Installation

The suite is designed to be highly portable with minimal dependencies.

**1. Clone the repository:**
```bash
git clone https://github.com/YOUR_USERNAME/NetAuditor-Suite.git
cd NetAuditor-Suite
```
**2. Create a virtual environment (Highly Recommended):**
```bash
python -m venv venv
source venv/bin/activate  # On Windows use: venv\Scripts\activate
```
**3. Install the global requirements:**
```bash
pip install -r requirements.txt
```
*(This will install the required core libraries like scapy and colorama for all the tools in the suite).*

## Current Development

As you can see from the tools status I am currently working on two more advanced projects, `HTTPSAuditor` to get into an up-to-date method of tunneling to and from outside networks. This project will allow me to get a further understanding of behavioural analysis and finding other aspects to monitor apart from the data itself.

Currently thinking about a `SMBAuditor` which will be a detector for SMB lateral movement inside the network, instead of outside tunneling like the other projects.

This project started as just the DNSAuditor to improve my scripting skills and get further into network analysis, let's see where it will end up!
