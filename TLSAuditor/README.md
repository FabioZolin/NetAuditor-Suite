# TLSAuditor
**TLSAuditor** is a Python-based Network Threat Hunting tool designed to analyze static network captures (.pcap) and detect advanced Command & Control (C2) infrastructure hiding within encrypted TLS/HTTPS traffic. 

Modern C2 frameworks (like Cobalt Strike, Sliver, or Brute Ratel) heavily rely on TLS to encrypt their payloads and blend in with regular web traffic. Instead of relying on static signatures or payload decryption, **TLSAuditor focuses on behavioral and structural network anomalies**, analyzing connection metadata, timing patterns, and TLS handshake fingerprints.

By splitting the detection logic into two highly specialized modules, this tool effectively counters both asynchronous beaconing and persistent tunneled connections.

---

## Architecture & Modules

The tool is divided into two separate modules, each targeting a specific evasion technique.

    TLSAuditor/
    ├── TLSAuditor_CLTHello.py   # The TLS Hello beaconing finder
    ├── TLSAuditor_Flow.py       # The TLS flow analyzer
    ├── README.md                # This file
    ├── requirements.txt         # Dependencies
    └── Docs/                    # Module and general architecture documentation
        ├── HelloDocs.md 
        ├── FlowDocs.md
        └── Architecture.md                    
                     

### 1. CLTHello
Designed to catch **Asynchronous Beaconing**. Many C2 agents wake up, open a new TLS connection, send a quick heartbeat/request (Client Hello), and close the connection immediately to sleep. 

This tool utilizes a **Sliding Window with Dynamic Relative Clustering** algorithm to identify the "Stepped Profiles" typical of modern C2 frameworks (e.g., switching from frequent beaconing in interactive mode to sleeping for several minutes, while still maintaining a somewhat regular mechanical pattern), finding patterns where static analysis will miss them.

**Core Capabilities:**
* **Advanced Timing Analysis:** Detects beaconing patterns even when the malware dynamically changes its callback frequency, tolerating network latency and high jitter without generating fragmented results.
* **SNI Entropy Check:** Calculates Shannon entropy to uncover domains generated via DGA (Domain Generation Algorithms).
* **Light Fingerprinting:** Detects deprecated TLS versions (SSLv3, TLS 1.0/1.1) and anomalies in the expected number of Cipher Suites.
* **Volumetric Spam Detection:** Identifies compromised IPs that saturate the network with repeated Client Hello requests due to connection failures.
* **Low Memory Footprint:** Uses Scapy's streaming read (`PcapReader`) to analyze multi-gigabyte PCAP files without exhausting RAM.

### 2. Flow
Designed to catch **Persistent Tunnels and Interactive Sessions**. Some tools (like reverse shells, proxy chains like Chisel, or constant data exfiltration scripts) keep a single, long-lived connection open, periodically pushing data back and forth.

This module acts as a **Stateful Flow Auditor**. It tracks the complete `(IP_src, Port_src, IP_dst, Port_dst)` 4-tuple, monitoring the time delta between `PSH` (Push) flags within the same session.

This module as well uses the **sliding window** and **window clustering** mechanics of the first one

**Core Capabilities:**
* **Long-Lived Tunnel Detection:** Flags encrypted sessions that remain active beyond a normal user-interaction threshold, leaving the final triage to the analyst.
* **Intra-Flow Beaconing:** Calculates timing jitter *inside* a single persistent connection to spot polling (e.g., an interactive shell checking for commands every 5 seconds).
* **Lazy DPI (Deep Packet Inspection):** Intelligently stops inspecting packet payloads immediately after the TLS handshake (or after a set threshold of non-TLS packets), saving massive amounts of CPU cycles.
* **Port-Reuse Handling:** Employs an Inactivity Timeout mechanism to cleanly close and reset sessions if an ephemeral port is reused by the OS, preventing data corruption.

---


## Quick Start
Before launching the commands be sure to be in the NetAuditor-Suite directory
### Hunting for Beacons (CLTHello)
Analyze a PCAP for discrete sleep/jitter patterns and structural anomalies on Client Hellos (e.g., allowing up to 50% Jitter):
    
> python ./TLSAuditor/TLSAuditor_CLTHello.py -f [path/to/]suspicious_traffic.pcap -wl [path/to/]whitelist.txt -jt 50 -bc 15 -v

*(Note: Timing analysis can be disabled with `-toff` if you only wish to focus on structural fingerprinting like TLS versions or DGA domains).*

### Hunting for Tunnels (Flow)
Analyze a PCAP for long-lived active sessions and intra-flow payload beaconing:
    
> python ./TLSAuditor/TLSAuditor_Flow.py -f [path/to/]suspicious_traffic.pcap -wl [path/to/]whitelist.txt -maxd 3600

---

## Suggestions

### Whitelisting

Many legitimate processes and services (e.g., Microsoft Updates, Google Telemetry, Apple Push Notifications) use regular TLS communication patterns. **A proper setup of whitelisted IPs and domains specific to the analyzed network is mandatory to prevent false positives.**

Create a simple `whitelist.txt` file containing trusted IPs or SNI root domains (one per line). The algorithm features **Smart Domain Suffix Matching**: inserting a root domain will automatically ignore all of its subdomains as well.
Lines containing subdomains will make it so the script ignores just the specified subdomain.

    # Example whitelist.txt
    microsoft.com
    bing.com
    services.google.com
    192.168.1.254

Pass it to the scripts using the `-wl` flag. The scripts use set-lookups, dropping trusted traffic instantly and drastically reducing execution time.

### Packet Filtering

To have a faster analysis it's ideal to filter the capture for TLS traffic in the capture file before launching the scripts, this way the scripts can focus on analyzing packets and not parsing through thousands of unrelated traffic.

**Important Note on the `-a` / `--all_tcp` flag:** If you intend to use the `-a` flag in `TLSAuditor_Flow.py` to hunt for TLS, or even clear TCP sessions, in the PCAP watch out for any excessive pre-filtering, as it will completely negate the purpose of the `-a` flag.

---

## 📚 Documentation

For a detailed breakdown of arguments, mathematical clustering logic, and thresholds you can refer to these files:
- [TLSAuditor_CLTHello](./Docs/HelloDocs.md)
- [TLSAuditor_Flow](./Docs/FlowDocs.md)
- [General Architecture Info](./Docs/Architecture.md)