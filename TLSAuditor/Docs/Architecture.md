# TLS Auditor: Technical Documentation

## 1. Beaconing Detection: Sliding Window & Clustering Algorithm

The scripts detect Command and Control (C2) beaconing by analyzing the time intervals (deltas) between packets. Because real-world network traffic introduces delays and attackers intentionally add randomization (jitter) to evade detection, the scripts use a combination of a **sliding window** and a **relative clustering algorithm** to identify periodic communication profiles.

### Phase 1: The Sliding Window
Instead of looking at the entire connection at once, the algorithm evaluates smaller, rolling subsets of packet deltas. This prevents localized network lag or stepped profiles from ruining the analysis.

1. **Timestamp Extraction:** * In `TLSAuditor_CLTHello.py`, timestamps are tracked per `(Source IP, Target)` pair. 
   * In `TLSAuditor_Flow.py`, timestamps are tracked per bidirectional flow, specifically looking at packets with the TCP `PSH` (Push) flag set.
2. **Delta Calculation:** The time difference between consecutive packets is calculated. 
3. **Windowing:** A sliding window of size `N` (defined by the user as `min_beacon_count`) moves across the list of deltas. 
   * *Flow script implementation:* Uses a `collections.deque` with a fixed maximum length, inherently acting as a rolling window as new packets arrive.
   * *ClientHello script implementation:* Sorts all timestamps at the end of the capture and slices the resulting delta array iteratively.

### Phase 2: Mathematical Validation (Jitter)
For each window, the algorithm calculates if the packets within that specific timeframe exhibit a stable frequency. 

It calculates the Mean ($\mu$), Variance ($\sigma^2$), and Standard Deviation ($\sigma$) of the deltas in the current window:
$$\mu=\frac{1}{N}\sum_{i=1}^{N}\Delta_i$$
$$\sigma=\sqrt{\frac{1}{N}\sum_{i=1}^{N}(\Delta_i-\mu)^2}$$

The **Jitter Percentage** is then calculated to determine how much the intervals deviate from the mean:
$$\text{Jitter}=\left(\frac{\sigma}{\mu}\right)\times100$$

If this Jitter is less than or equal to the configured threshold (`jitter_threshold`), the window is flagged as a potential beaconing pattern and passed to the clustering engine.

### Phase 3: Dynamic Relative Clustering
Because an attacker might change their sleep times (e.g., sleeping for 5 seconds, then 60 seconds), the script categorizes the validated windows into distinct "clusters" or profiles.

1. **Tolerance Definition:** The algorithm uses the user's jitter percentage as a decimal tolerance ratio (e.g., 15% becomes `0.15`).
2. **Distance Calculation:** For a validated window's mean ($\mu$), the script checks existing clusters to find the closest fit. It calculates the relative difference ratio against an existing cluster's center ($C$):
   $$\text{Ratio}=\frac{|\mu-C|}{C}$$
3. **Cluster Assignment:**
   * **Match found:** If the ratio is within the tolerance and is the minimum distance found, the window is added to that cluster. The cluster's "center of gravity" is dynamically recalculated as the average of all means assigned to it.
   * **No match:** If the window's mean falls outside the tolerance of all existing clusters, a new cluster is created with this mean as its initial center.

---

## 2. Core Data Structures

Both scripts utilize memory-efficient data structures from the Python standard library.

### `TLSAuditor_CLTHello.py` Data Structures

Because this script primarily analyzes single packets (Client Hellos) in a streaming fashion, its data structures are designed for aggregation and volumetric tracking.

* **`HTTPSStats` (Class):** The central state manager.
    * `timing_tracker`: A `collections.defaultdict(list)`. Maps a tuple key of `(Source IP, SNI or Destination IP)` to a flat list of `[timestamps]`. Analyzed post-capture.
    * `suspicious_ips` & `client_hello_counts`: `collections.Counter` objects. Used to keep count of scores and volumetric spam per IP address without needing `KeyError` checks.
    * *Standard Attributes:* Integers tracking global counts (`total_client_hellos`, `missing_sni`, `missing_alpn`, etc.).
* **`discovered_clusters` (List of Dicts):** Generated dynamically during beaconing analysis. Each dictionary represents a sleep profile:
    * `center` (float): The current moving average of the cluster.
    * `count` (int): Number of sliding windows that fit into this cluster.
    * `jitters` (list): Array of jitter percentages for calculating the cluster's final average jitter.
    * `all_means` (list): Array of every window mean assigned here, used to safely recalculate the `center`.

### `TLSAuditor_Flow.py` Data Structures

This script requires stateful tracking of bidirectional TCP connections, meaning its data structures are built to handle active lifecycles and early exits (Lazy DPI).

* **`TLSSession` (Class):** Represents a single bidirectional TCP flow.
    * `start_time`, `last_ts`, `duration` (floats): Manage session lifecycle and timeouts.
    * `last_psh_ts` (float): Tracks the timestamp of the last packet carrying a TCP payload.
    * `deltas`: A `collections.deque(maxlen=window_size)`. A highly efficient rolling queue. As new deltas are appended, the oldest ones are automatically dropped, natively functioning as the sliding window.
    * `discovered_clusters` (List of Dicts): Same cluster structure as above, but tracked *per session* rather than globally.
    * `packet_count` (int): Counter to keep track of the number of packets from the session   
    * `inspect_payload` (bool): A critical optimization flag. Set to `False` once the Client Hello is parsed or after 15 packets, preventing Scapy from executing costly DPI on encrypted application data.
    * `ignore` (bool): Flag set to True if the session is found to be with a whitelisted SNI or the TLS Client Hello is not found; sessions flagged wont be analyzed.
    * `closed` (bool): Flag set to True after both client and server have sent the FIN flag to close the connection, necessary for smooth session closure
    * `fin_senders` (set): Allows to properly track the FIN seding from client and server, if the set contains 2 ip's the closed flag will be set to true.
    * `sni` (string): Saves the SNI associated with the session found in the client hello, if present
    * `client_hello_seen` (bool): Flags if the client hello has been seen in the session
* **`HTTPSStats` (Class):** The global flow orchestrator.
    * `active_sessions`: A dictionary mapping a unique `flow_key` to a `TLSSession` object. The `flow_key` is a tuple of the two endpoints (`IP:Port`) sorted alphabetically to ensure packets from either direction hit the same session state.
    * `completed_sessions`: A list of tuples `(flow_key, TLSSession)`. Sessions are moved here when a `FIN/RST` flag is seen or when the timeout sweeper clears them from memory.
    * `suspicious_ips`: A `collections.Counter` for tracking final anomaly scores.
    * `total_packets`: A counter to keep count of the total of parsed packets used for garbage collections.