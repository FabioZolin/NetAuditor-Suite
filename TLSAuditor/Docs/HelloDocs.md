# CLTHello Docs

**TLSAuditor_CLTHello** is a Network Threat Hunting tool written in Python, designed to analyze static network capture files (.pcap) and detect malicious communications (Command & Control), advanced beaconing, and structural anomalies in TLS protocol traffic.

Unlike static analyzers, this tool utilizes a **Sliding Window with Dynamic Relative Clustering** algorithm to identify the "Stepped Profiles" typical of modern C2 frameworks like Cobalt Strike, Sliver, or Brute Ratel.
These profiles often switch from beaconing often in their interactive mode to sleeping several minutes but still maintaining a somewhat regular pattern.

The timing analysis can also be turned off if the user wishes to focus on other information such as TLS versions, traffic volumes, randomly generated domains.

## Usage

Basic execution:

> python TLSAuditor_CLTHello.py -f traffic.pcap

Execution with Whitelist and aggressive analysis (e.g., 50% Jitter):

> python TLSAuditor_CLTHello.py -f traffic.pcap -wl whitelist.txt -jt 50 -bc 15 -v

### Command Line Arguments

| Argument | Description | Default |
| :--- | :--- | :--- |
| -f, --file | **(Required)** Path to the .pcap file to analyze. | N/A |
| -wl, --whitelist | Text file containing domains/IPs to ignore (one per line). | None |
| -jt, --jitter | Max allowed Jitter threshold (%) to flag a mechanical pattern. | 20.0 |
| -bc, --min_beacon_count| Sliding window size (minimum packets required for a pattern). | 10 |
| -mv, --max_volume | Max Client Hello allowed per IP before flagging as SPAM. | 500 |
| -cc, --ciphers | Minimum expected Cipher Suites in the Client Hello. | 5 |
| -et, --entropy | Minimum Shannon Entropy score to detect DGA domains. | 4.0 |
| -vo, --version_off | Disables alerting for deprecated TLS versions. | False |
| -toff, --timing_off | Disables temporal analysis and beaconing detection. | False |
| -v, -vv | Enables Verbose / Very Verbose mode for real-time alerts. | False |

### Suggestion

Many legitimate processes and services use regular TLS communications patterns, a proper setup of whitelisted IPs and domains specific to the analyzed network and host is mandatory to get a proper report.
Still the tool lets the user get a complete image of the patterns which can then be inspected to find if they come from legitimate services or are actual IoCs.

## Whitelist Format (whitelist.txt)
Insert one root domain or IP per line. The algorithm will automatically ignore all of its subdomains as well.

> microsoft.com

> bing.com

> 192.168.1.254

## Anomaly Weighting
The tool utilizes an internal scoring system to rank the most suspicious IP addresses. The final leaderboard is calculated by combining structural anomalies found within individual Client Hello packets and behavioral anomalies analyzed over the entire capture.

### Behavioral & Volumetric Penalties (Global):
* **Beaconing Profiles:** The tool focuses heavily on timing analysis. Based on the timing pattern a different penalty is added for each found window: 
The "timing" column represents the time passed between a packet and the other in the suspicious window

| Timing (s) | Penalty |
| :--- | :--- |
| t<20 | 20 |
| 20<=t<3600 | 50 |
| t>=3600 | 100 |

* **Volumetric Spam:** If an IP sends more Client Hellos than the allowed `max_volume` threshold, it receives a heavy penalty (**+500 points**).

### Structural Penalties (Per Packet):
Individual packets accumulate points based on fingerprinting anomalies. *Note: To prevent noise, structural points are only added to an IP's total score if a single packet accumulates a minimum of 3 points.*
* **Deprecated TLS Version:** Connection attempts using SSLv3, TLS 1.0, or TLS 1.1 (**+5 points**).
* **DGA / High Entropy SNI:** The SNI string exceeds the Shannon entropy threshold (**+3 points**).
* **Low Cipher Suites:** The packet contains fewer cipher suites than the expected threshold (**+3 points**).
* **Missing SNI:** The Server Name Indication extension is absent (**+2 points**).
* **Missing ALPN:** The Application-Layer Protocol Negotiation extension is absent (**+1 point**).

If you wish to focus strictly on structural fingerprinting, the timing analysis can be disabled entirely using the `-toff` flag so beaconing scores do not overshadow packet-level anomalies.

