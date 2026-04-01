# TLSAuditor_Flow Docs

**TLSAuditor_Flow** is a Network Threat Hunting tool written in Python, designed to analyze network capture files (.pcap or .pcapng) and detect malicious communications, specifically Command & Control (C2) tunnels and HTTPS beaconing behavior.

Unlike standard static analyzers, this tool utilizes a **Flow-Based Temporal Analysis** combined with a **Scapy Lazy DPI (Deep Packet Inspection)** approach. It monitors the time deltas between TCP PSH flags to dynamically cluster beaconing profiles based on Jitter variance. To optimize CPU usage, the DPI engine extracts the Server Name Indication (SNI) from the initial TLS Client Hello and then gracefully stops inspecting the payload for the remainder of the session.

## Usage

Basic execution:

> python TLSAuditor_Flow.py -f traffic.pcap

Execution with a Whitelist, stricter Jitter tolerance, and aggressive beaconing window:

> python TLSAuditor_Flow.py -f traffic.pcap -wl whitelist.txt -jt 10.0 -bc 5

### Command Line Arguments

| Argument | Description | Default |
| :--- | :--- | :--- |
| -f, --file | **(Required)** Path to the .pcap or .pcapng file to analyze. | N/A |
| -wl, --whitelist | Path to a text file containing domains/IPs to ignore (one per line). | None |
| -jt, --jitter | Maximum allowed Jitter threshold (%) to flag a possible mechanical beaconing pattern. | 20.0 |
| -bc, --min_beacon_count| Minimum number of packets (sliding window size) required to consider a flow for C2 analysis. | 10 |
| -to, --timeout | Max inactivity in seconds before considering a session closed/inactive. | 300 |
| -maxd, --max_duration | Maximum duration of a connection in seconds before flagging it as suspiciously long. | 3600 |
| -mdlt, --min_delta | Minimum delta between packets to consider the packets for calculations | 1 |
| -a, --all_tcp | Analyzes all tcp traffic without ignoring if the connection doesnt have a TLS handshake | False |

### Suggestions
#### Whitelisting
Many legitimate background processes, cloud syncing tools, and services use regular polling patterns or long sessions over TLS that resemble C2 beaconing. A proper setup of whitelisted IPs and domains specific to the analyzed network and host is **mandatory** to get a clean report.
The tool provides a comprehensive view of these patterns, including the extracted SNI, which you can use to quickly discern whether the traffic originates from a legitimate service or represents an actual IoC.
#### Min Delta
Modifying the min_delta is suggested if parsing through the capture there is slow ACK flow, this can mess with the detection calculations, raising the min_delta can help fix it; on the flip side if there is insanely fast beaconing lowering this value can be helpful
#### All TCP
If the capture is a partial one it's possible the TLS handshake isnt present, to avoid missing possible C2 traffic it can be a good idea to turn it on. This flag is going to increase greatly the amount of packets took into consideration, expect a slower execution, whitelisting with this flag active is even more important than before.


## Whitelist Format (whitelist.txt)
Insert one root domain or IP per line. The analysis engine will automatically ignore the IPs or perform a dynamic check against the extracted SNI. 
If the captured SNI ends with a whitelisted domain, the session is immediately dropped to save processing power.

> microsoft.com

> bing.com

> services.google.com

> 192.168.1.254

## Anomaly Weighting
* **Beaconing Profiles:** The tool focuses on timing analysis. Based on the timing pattern a different penalty is added for each found window: 
The "timing" column represents the time passed between a packet and the other in the suspicious window

| Timing (s) | Penalty |
| :--- | :--- |
| t<20 | 20 |
| 20<=t<3600 | 50 |
| t>=3600 | 100 |

* **Session Duration:** If a session is kept active for longer than the `max_duration` threshold, the IP addresses involved receive a heavy penalty (**+500 points**).
