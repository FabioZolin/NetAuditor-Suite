import argparse
import sys
import os
import math
import logging
from collections import defaultdict, Counter

# --- SCAPY SETUP & LOGGING ---
# Suppress Scapy runtime warnings (e.g., unknown GREASE cipher suites)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import PcapReader, IP, IPv6, load_layer
# Load TLS module globally
load_layer("tls")

from scapy.layers.tls.handshake import TLSClientHello
from scapy.layers.tls.extensions import TLS_Ext_ServerName, TLS_Ext_ALPN
from scapy.layers.tls.record import TLS

try:
    from colorama import init, Fore, Style
    # --- COLOR DEFINITIONS ---
    C_CRIT = Fore.RED + Style.BRIGHT
    C_WARN = Fore.YELLOW + Style.BRIGHT
    C_ANOMALY = Fore.MAGENTA + Style.BRIGHT
    C_INFO = Fore.CYAN
    C_RESET = Style.RESET_ALL
    init(autoreset=True)
except ImportError:
    C_CRIT = C_WARN = C_ANOMALY = C_INFO = C_RESET = ""


# --- DATA STRUCTURES ---

class HTTPSStats:
    """Class to maintain the state of the HTTPS/TLS analysis."""
    def __init__(self):
        self.total_client_hellos = 0
        self.missing_sni = 0
        self.missing_alpn = 0
        self.deprecated_tls = 0
        self.low_ciphers = 0
        
        # Timing Dictionary: Key -> (IP_Src, Target_SNI_or_IP), Value -> [timestamp1, timestamp2, ...]
        self.timing_tracker = defaultdict(list)
        
        # Anomaly scoring and volumetric tracking
        self.suspicious_ips = Counter()
        self.client_hello_counts = Counter()


def print_banner():
    """Prints the ASCII art banner and tool name."""
    banner = f"""{C_INFO}
     _______ _       _____ _    _      _ _        _____ ___  
    |__   __| |     / ____| |  | |    | | |      / ____|__ \\ 
       | |  | |    | (___ | |__| | ___| | | ___ | |       ) |
       | |  | |     \\___ \\|  __  |/ _ \\ | |/ _ \\| |      / / 
       | |  | |____ ____) | |  | |  __/ | | (_) | |____ / /_ 
       |_|  |______|_____/|_|  |_|\\___|_|_|\\___/ \\_____|____|
                                                   
                    -- TLS Beaconing Auditor v1.0 --  
                          -- by Fabio Zolin --                 
    {C_RESET}"""
    print(banner)

# --- ORCHESTRATOR & PARSER ---

def analyze_https_pcap(pcap_file, config):
    """
    Main function to read the PCAP file in streaming mode and route packets.
    """
    if not os.path.isfile(pcap_file):
        print(f"{C_CRIT}[ERROR]{C_RESET} File '{pcap_file}' does not exist.")
        sys.exit(1)

    print(f"{C_INFO}[INFO]{C_RESET} Starting HTTPS/TLS analysis on: {pcap_file}...")
    print(f"{C_WARN}[WAIT]{C_RESET} Scapy is processing the PCAP (Streaming mode)...")
    
    stats = HTTPSStats()

    try:
            with PcapReader(pcap_file) as packets:
                for packet in packets:

                    is_client_hello = False

                    # TLS Handshake check
                    #If it's on native port 443 it's recognised by scapy
                    if packet.haslayer("TLSClientHello"):
                        is_client_hello = True

                    # If it's on strange ports we need to ckeck bytes manually
                    elif packet.haslayer("TCP") and packet.haslayer("Raw"):
                        payload = bytes(packet["Raw"])
                        # Check HEX signature: 0x16 (Handshake), 0x03 (TLS), ..., 0x01 (Client Hello)
                        if len(payload) > 5 and payload[0] == 0x16 and payload[1] == 0x03 and payload[5] == 0x01:
                            try:
                                # Force TLS decoding
                                tls_layer = TLS(payload)
                                if tls_layer.haslayer("TLSClientHello"):
                                    # Replace the Raw layer with the decoded TLS layer
                                    packet["Raw"].underlayer.remove_payload()
                                    packet /= tls_layer
                                    is_client_hello = True
                            except Exception as e:
                                print(f"\n{C_CRIT}[ERROR]{C_RESET} Error while parsing raw TLS: {e}")

                    # If a client hello is found, we process it and extract metadata
                    if is_client_hello:
                        stats.total_client_hellos += 1
                        process_client_hello(packet, stats, config)

                        if stats.total_client_hellos % 500 == 0:
                            print(f"\r[~] {C_INFO} {stats.total_client_hellos} Clt Hello packets processed...{C_RESET}", end="", flush=True)

    except Exception as e:
        print(f"\n{C_CRIT}[ERROR]{C_RESET} Unexpected error while reading PCAP: {e}")

    print(f"\r{C_INFO}[INFO]{C_RESET} Scan completed. Found {stats.total_client_hellos} Client Hello packets.       ")
    
    # Execute final analysis modules
    if not config.get('timing_off'):
        calculate_beaconing(stats, config)
    
    print_report(stats, config)


def calculate_shannon_entropy(data):
    """Calculates Shannon entropy to detect pseudo-random strings (e.g., DGA SNIs)."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    occurences = Counter(data)
    for count in occurences.values():
        p_x = count / length
        entropy -= p_x * math.log2(p_x)
    return entropy
 
def set_whitelist(config):
    whitelist_set = set()
    if config.get('whitelist') and os.path.isfile(config['whitelist']):
        with open(config['whitelist'], 'r', encoding='utf-8') as f:
            # Save everything in lowercase, ignore empty lines and strip whitespace
            whitelist_set = {line.strip().lower() for line in f if line.strip()}
        print(f"{C_INFO}[INFO]{C_RESET} {len(whitelist_set)} domains/IPs loaded from whitelist.")
    config['whitelist_set'] = whitelist_set

def process_client_hello(packet, stats, config):
    """
    Extracts metadata from the Client Hello using Scapy, checks for whitelisting.
    Executes TLS Version, Cypher count, SNI, ALPN checks.
    """
    try:
        # Default IP in case extraction fails unexpectedly
        ip_src = "Unknown" 
        
        # IP Extraction (IPv4 or IPv6)
        if packet.haslayer(IP):
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
        elif packet.haslayer(IPv6):
            ip_src = packet[IPv6].src
            ip_dst = packet[IPv6].dst
        else:
            return
        
        # Volumetric Tracking: Count Client Hellos per source IP
       

        tls_hello = packet[TLSClientHello]
        anomaly_score = 0
        sni = None
        alpn = None
        whitelist = config.get('whitelist_set')

        # --- SCAPY TLS FIELD EXTRACTION ---

        # 1. SNI (Server Name Indication)
        if packet.haslayer(TLS_Ext_ServerName):
            server_names = packet[TLS_Ext_ServerName].servernames
            if server_names and len(server_names) > 0:
                raw_sni = server_names[0].servername
                # Checks if it needs decoding or if it's already a string
                sni = raw_sni.decode('utf-8', errors='ignore') if isinstance(raw_sni, bytes) else str(raw_sni)


        #SNI Whitelist check
        if whitelist:
        # If SNI is present, we check it against the whitelist; if not, we fallback to the destination IP for matching
            target_to_check = (sni.lower() if sni else ip_dst)
            # Exact match (es. bing.com) or suffix match (es. www.bing.com)
            if any(target_to_check == w or target_to_check.endswith("." + w) for w in whitelist):
                return # If it's whitelisted, we skip all further checks for this packet
            
        # 2. ALPN (Application-Layer Protocol Negotiation)
        if packet.haslayer(TLS_Ext_ALPN):
            protocols = packet[TLS_Ext_ALPN].protocols
            if protocols and len(protocols) > 0:
                raw_alpn = protocols[0]
                # Same check as before for the string extraction
                alpn = raw_alpn.decode('utf-8', errors='ignore') if isinstance(raw_alpn, bytes) else str(raw_alpn)

        # 3. TLS Version (Scapy returns an integer, e.g., 769 = 0x0301 = TLS 1.0)
        tls_version = tls_hello.version
        
        # 4. Cipher Suites (Parsed as a native Python list by Scapy)
        cipher_count = len(tls_hello.ciphers) if tls_hello.ciphers else 0

        

        # --- TIMING TRACKER ---
        if not config.get('timing_off'):
            timestamp = float(packet.time) 
            safe_sni = sni if sni else ip_dst
            tracker_key = (ip_src, safe_sni)
            stats.timing_tracker[tracker_key].append(timestamp)



        stats.client_hello_counts[ip_src] += 1

        # --- HEURISTIC CHECKS ---

        # MISSING SNI
        if not sni:
            stats.missing_sni += 1
            anomaly_score += 2
            if config.get('very_verbose'):
                print(f"{C_WARN}[WARNING]{C_RESET} {ip_src} -> {ip_dst} | Missing SNI")
        else:
            # SNI ENTROPY CHECK (DGA Detection)
            entropy = calculate_shannon_entropy(sni)
            if entropy >= config.get('entropy_threshold', 4.0):
                anomaly_score += 3
                if config.get('verbose'):
                    print(f"{C_ANOMALY}[DGA ANOMALY]{C_RESET} {ip_src} | High entropy SNI: {sni} (Score: {entropy:.2f})")

        # MISSING ALPN
        if not alpn:
            stats.missing_alpn += 1
            anomaly_score += 1
            if config.get('very_verbose'):
                print(f"{C_WARN}[WARNING]{C_RESET} {ip_src} -> {ip_dst} | Missing ALPN")

        # TLS VERSION CHECK (768 = SSLv3, 769 = TLS 1.0, 770 = TLS 1.1)
        if not config.get('version_off'):
            if tls_version in [768, 769, 770]:
                stats.deprecated_tls += 1
                anomaly_score += 5
                if config.get('verbose'):
                    print(f"{C_CRIT}[CRITICAL]{C_RESET} {ip_src} -> {ip_dst} | Deprecated TLS Version (Int: {tls_version})")          

        # CIPHER SUITES COUNT CHECK
        if cipher_count < config.get('min_ciphers', 5):
            if cipher_count > 0:
                stats.low_ciphers += 1
                anomaly_score += 3
                if config.get('verbose'):
                    print(f"{C_ANOMALY}[ANOMALY]{C_RESET} {ip_src} -> {ip_dst} | Low Cipher Suites count: {cipher_count} (SNI: {sni})")

        # SCORE UPDATER
        if anomaly_score >= 3:
            stats.suspicious_ips[ip_src] += anomaly_score

    except Exception as e:
        # Failsafe for highly malformed packets
        if config.get('very_verbose'):
            print(f"Parsing error on packet from {ip_src}: {e}")


def calculate_beaconing(stats, config):
    """
    Analyzes timestamps with a Sliding Window and uses a Relative Clustering algorithm
    to group sleep profiles even with very high Jitter.
    """
    print(f"\n{C_INFO}[INFO]{C_RESET} Temporal analysis in progress...")
    
    found_beaconing = False
    window_size = config['min_beacon_count']
    # Trasforming the jitter threshold from percentage to ratio (e.g., 50.0 -> 0.50) for clustering
    clustering_tolerance = config['jitter_threshold'] / 100.0 
    
    for (ip_src, target), timestamps in stats.timing_tracker.items():
        
        if len(timestamps) < window_size + 1:
            continue
            
        timestamps.sort()
        deltas = [timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))]
        
        # List of ditcionaries for clusters, each one has a "center" (mobile average), a count of how many windows belong to it, and a list of jitters for those windows to calculate the average jitter at the end
        discovered_clusters = [] 
        
        for i in range(len(deltas) - window_size + 1):
            window = deltas[i : i + window_size]
            
            mean_delta = sum(window) / window_size
            if mean_delta == 0:
                continue
                
            variance = sum((d - mean_delta) ** 2 for d in window) / window_size
            std_dev = math.sqrt(variance)
            jitter_percent = (std_dev / mean_delta) * 100
            
            if jitter_percent <= config['jitter_threshold']:
                
                # --- CLUSTERING ALGORITHM ---
                best_cluster = None
                min_diff_ratio = float('inf')
            
                # Searching the cluster closer to the found mean, using a relative difference ratio to allow dynamic tolerance based on the cluster center.
                for cluster in discovered_clusters:
                    # Calculating the relative difference ratio between the new mean and the cluster center
                    diff_ratio = abs(mean_delta - cluster['center']) / cluster['center']
                    
                    # If the difference ratio is within the clustering tolerance, we consider it for inclusion in that cluster. 
                    # Among all clusters that meet this condition, we choose the one with the smallest difference ratio as the best match for this window.
                    if diff_ratio <= clustering_tolerance:
                        if diff_ratio < min_diff_ratio:
                            min_diff_ratio = diff_ratio
                            best_cluster = cluster
                            
                if best_cluster:
                    # Add data to the existing cluster and update its center
                    best_cluster['count'] += 1
                    best_cluster['jitters'].append(jitter_percent)
                    best_cluster['all_means'].append(mean_delta)
                    # Ricalcoliamo il "centro di gravità" del cluster
                    best_cluster['center'] = sum(best_cluster['all_means']) / len(best_cluster['all_means'])
                else:
                    # Create a new cluster if no existing one is close enough to the current mean
                    discovered_clusters.append({
                        'center': mean_delta,
                        'count': 1,
                        'jitters': [jitter_percent],
                        'all_means': [mean_delta]
                    })
        
        # 3. Output
        if discovered_clusters:
            found_beaconing = True
            print(f"\n{C_CRIT}[Possible Beaconing Detected]{C_RESET}")
            print(f" {C_WARN}Target:{C_RESET} {ip_src} -> {target}")
            print(f" {C_WARN}Total Packets:{C_RESET} {len(timestamps)}")
            print(f" {C_WARN}Profiles Found:{C_RESET}")
            
            #Printing the cluster information, rounding the center to the nearest second for easier interpretation, and calculating the average jitter for that cluster.
            for cluster in discovered_clusters:
                freq = int(round(cluster['center']))
                avg_jitter = sum(cluster['jitters']) / len(cluster['jitters'])
                print(f"   ► Pattern at ~{freq} sec sleep | Windows: {cluster['count']} | Average Jitter: {avg_jitter:.2f}%")
                if freq < 20 :
                    score = (20 *cluster['count'])
                elif 20 <= freq < 3600:
                    score = (50 *cluster['count'])
                else:
                    score = (100 * cluster['count'])
                stats.suspicious_ips[ip_src] += score
            
    if not found_beaconing:
        print(f"{C_INFO}[+] No beaconing behaviour detected.{C_RESET}")


def print_report(stats, config):
    """
    Prints the final analysis summary.
    """
    print(f"\n{C_INFO}=================================================={C_RESET}")
    print(f"{C_INFO}              FINAL HTTPS/TLS REPORT              {C_RESET}")
    print(f"{C_INFO}=================================================={C_RESET}")
    print(f" Total Client Hellos analyzed : {stats.total_client_hellos}")
    print(f" Packets missing SNI          : {stats.missing_sni}")
    print(f" Packets missing ALPN         : {stats.missing_alpn}")
    print(f" Packets with deprecated TLS  : {stats.deprecated_tls}")
    print(f" Packets with low Ciphers     : {stats.low_ciphers}")
    
    # VOLUMETRIC ANOMALIES (Spamming)
    print(f"\n{C_CRIT}--- VOLUMETRIC ANOMALIES (CLIENT HELLO) ---{C_RESET}")
    volume_threshold = config.get('max_volume', 500)
    volumetric_anomalies = False
    
    for ip, count in stats.client_hello_counts.items():
        if count > volume_threshold:
            volumetric_anomalies = True
            print(f" {C_WARN}[SPAM DETECTED]{C_RESET} IP {ip} sent {count} Client Hellos! (Threshold: {volume_threshold})")
            stats.suspicious_ips[ip] += 500

    if not volumetric_anomalies:
        print(f" {C_INFO}No IP generated an anomalous volume of requests.{C_RESET}")

    # SUSPICIOUS IPs RANKING
    print(f"\n{C_CRIT}--- SUSPICIOUS SOURCE IPs ---{C_RESET}")
    if not stats.suspicious_ips:
        print(f" {C_INFO}No IP exceeded the anomaly thresholds. Network appears clean.{C_RESET}")
    else:
        # Print IPs with the highest anomaly scores in descending order
        for ip, score in stats.suspicious_ips.most_common():
            print(f" [!] IP: {ip} | Anomaly Score: {score}")
    print(f"{C_INFO}=================================================={C_RESET}\n")


# --- ARGPARSE SETUP ---

def main():
    parser = argparse.ArgumentParser(description="PCAP analyzer to detect HTTPS/TLS C2 beaconing, SNI anomalies, and legacy encryption.")
    print_banner()
    # Mandatory Argument
    parser.add_argument("-f", "--file", help="Path to the .pcap file to analyze", required=True)
    
    # Behavioral Thresholds (Timing & Volume)
    parser.add_argument("-jt", "--jitter", help="Max allowed jitter in percentage to flag as beaconing (default: 20.0%%)", type=float, default=20.0)
    parser.add_argument("-bc", "--min_beacon_count", help="Minimum number of packets to evaluate beaconing (default: 10)", type=int, default=10)
    parser.add_argument("-mv", "--max_volume", help="Max allowed Client Hellos per IP before flagging as spam (default: 500)", type=int, default=500)
    
    # Structural Thresholds (Light Fingerprinting)
    parser.add_argument("-cc", "--ciphers", help="Minimum expected Cipher Suites (below this is suspicious, default: 5)", type=int, default=5)
    parser.add_argument("-et", "--entropy", help="Minimum Shannon entropy score for SNI (DGA detection, default: 4.0)", type=float, default=4.0)

    # Tool switches
    parser.add_argument("-vo", "--version_off", help="Turns off flagging for deprecated TLS versions", action="store_true")
    parser.add_argument("-toff", "--timing_off", help="Turns off the timing analysis (beaconing detection)", action="store_true")
    parser.add_argument("-wl", "--whitelist", help="Path to a text file containing domains/IPs to ignore (one per line)", type=str, default=None)
    
    # Verbosity
    parser.add_argument("-v", "--verbose", help="Enable verbose mode displaying individual alerts", action="store_true")
    parser.add_argument("-vv", "--very_verbose", help="Enable very verbose mode, displaying all alerts and warnings", action="store_true")
    
    args = parser.parse_args()
    
    config = {
        'file': args.file,
        'jitter_threshold': args.jitter,
        'min_beacon_count': args.min_beacon_count,
        'max_volume': args.max_volume,
        'min_ciphers': args.ciphers,
        'entropy_threshold': args.entropy,
        'verbose': args.verbose,
        'very_verbose' : args.very_verbose,
        'version_off': args.version_off,
        'timing_off': args.timing_off,
        'whitelist' : args.whitelist
    }
    set_whitelist(config)
    if(not config['whitelist']):
        print(f"{C_WARN}[WARN]{C_RESET} No whitelist provided. All domains/IPs will be analyzed. Regular services will trigger multiple false alerts.")
    analyze_https_pcap(config['file'], config)

if __name__ == "__main__":
    main()