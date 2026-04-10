import argparse
import sys
import os
import logging
from collections import deque, Counter
import math
import tldextract
import functools

# Define the global extractor
extractor = tldextract.TLDExtract()

# --- SCAPY SETUP & LOGGING ---
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import PcapReader, IP, IPv6, TCP, load_layer
from scapy.layers.tls.record import TLS
from scapy.layers.tls.handshake import TLSClientHello
from scapy.layers.tls.extensions import TLS_Ext_ServerName



# Preventing scapy from interpreting TLS packets on its own for freedom of analysis
TCP.payload_guess = [rule for rule in TCP.payload_guess if rule[1] != TLS]

load_layer("tls")

try:
    from colorama import init, Fore, Style
    C_CRIT = Fore.RED + Style.BRIGHT
    C_WARN = Fore.YELLOW + Style.BRIGHT
    C_ANOMALY = Fore.MAGENTA + Style.BRIGHT
    C_INFO = Fore.CYAN
    C_RESET = Style.RESET_ALL
    init(autoreset=True)
except ImportError:
    C_CRIT = C_WARN = C_ANOMALY = C_INFO = C_RESET = ""

# --- DATA STRUCTURES ---

class TLSSession:
    def __init__(self, start_time, window_size=10):
        # General session timing info
        self.start_time = start_time
        self.last_ts = start_time
        self.duration = 0.0
        
        # Beaconing timing checks
        self.last_psh_ts = None
        self.deltas = deque(maxlen=window_size)
        self.discovered_clusters = []
        
        # Counters and flag for CPU optimization
        self.packet_count = 0
        self.inspect_payload = True  # Set to false after N non TLS packets or after seeing Client Hello to skip DPI
        self.ignore = False # Set to true if it's not a TLS session or whitelisted SNI
        self.closed = False
        self.fin_senders = set()
        
        # TLS data
        self.sni = None
        self.client_hello_seen = False

class HTTPSStats:
    def __init__(self):
        self.total_packets = 0
        self.active_sessions = {}    # { flow_key: TLSSession }
        self.completed_sessions = [] # Completed sessions for post-analysis
        self.suspicious_ips = Counter()

def print_banner():
    """Prints the ASCII art banner and tool name."""
    banner = f"""{C_INFO}
  _______ _       _____ ______ _                _____ ___  
 |__   __| |     / ____|  ____| |              / ____|__ \\ 
    | |  | |    | (___ | |__  | | _____      _| |       ) |
    | |  | |     \\___ \\|  __| | |/ _ \\ \\ /\\ / / |      / / 
    | |  | |____ ____) | |    | | (_) \\ V  V /| |____ / /_ 
    |_|  |______|_____/|_|    |_|\\___/ \\_/\\_/  \\_____|____|
                                                                                                   
                    -- TLS Flow C2 Auditor v1.0 --  
                        -- by Fabio Zolin --                 
    {C_RESET}"""
    print(banner)


# --- ANALYSIS ENGINE ---

@functools.lru_cache(maxsize=10000)
def get_target_info(target):
    """
    Extracts the core organization name from a domain or IP.
    Caches the result for high performance in streaming PCAPs.
    """
    if not target:
        return ""
    ext = extractor(target)
    return ext.domain

def set_whitelist(config):
    whitelist_set = set()
    if config.get('whitelist') and os.path.isfile(config['whitelist']):
        with open(config['whitelist'], 'r', encoding='utf-8') as f:
            for line in f:
                raw_target = line.strip().lower()
                
                # Ignore empty lines and comments
                if raw_target and not raw_target.startswith('#'):
                    # Extract the core name (e.g., "microsoft" or "8.8.8.8")
                    ext = extractor(raw_target)
                    if ext.domain:
                        whitelist_set.add(ext.domain)
                        
        print(f"{C_INFO}[INFO]{C_RESET} {len(whitelist_set)} core domains/IPs loaded from whitelist.")
    config['whitelist_set'] = whitelist_set


def get_bidirectional_key(packet):
    """Create a unique key (EndpointA <-> EndpointB) sorted alphabetically."""
    if packet.haslayer(IP):
        ip_src, ip_dst = packet[IP].src, packet[IP].dst
    elif packet.haslayer(IPv6):
        ip_src, ip_dst = packet[IPv6].src, packet[IPv6].dst
    else:
        return None, None, None

    if packet.haslayer(TCP):
        port_src, port_dst = packet[TCP].sport, packet[TCP].dport
        endpoint1 = f"{ip_src}:{port_src}"
        endpoint2 = f"{ip_dst}:{port_dst}"
        return tuple(sorted([endpoint1, endpoint2])), ip_src, ip_dst
        
    return None, None, None

def process_packet(packet, stats, config):
    """Processes the single TCP packet, updating session states with eventual closure handling and calculating timing deltas for beaconing detection."""
    flow_key, ip_src, ip_dst = get_bidirectional_key(packet)
    if not flow_key:
        return

    ts = float(packet.time)
    tcp_layer = packet[TCP]

    whitelist = config.get('whitelist_set')
    if whitelist:
        # If the IP source or destination is in the whitelist, skip
        if get_target_info(ip_src) in whitelist or get_target_info(ip_dst) in whitelist:
            return


    # --- 1. SESSION MANAGEMENT ---
    if flow_key not in stats.active_sessions:
        if 'F' in tcp_layer.flags or 'R' in tcp_layer.flags:
            return
        stats.active_sessions[flow_key] = TLSSession(start_time=ts, window_size=config['min_beacon_count'])
    
    # Grabs the session for the current flow, we will need it for both closure handling and timing checks
    session = stats.active_sessions[flow_key]

    session.packet_count += 1
    session.last_ts = ts
    session.duration = ts - session.start_time

    # --- 1.2 SESSION CLOSURE (FIN/RST) ---
    # # 1. Handle Abrupt RST (Immediate Kill)
    if 'R' in tcp_layer.flags:
        if flow_key in stats.active_sessions:
            session = stats.active_sessions.pop(flow_key)
            if not session.ignore:
                stats.completed_sessions.append((flow_key, session))
        return

    # 2. Handle FIN from both sides
    if 'F' in tcp_layer.flags:
        session.fin_senders.add(ip_src) # Record the IP sending the FIN
        
        # If both sides have sent a FIN, the connection is effectively dead
        if len(session.fin_senders) == 2:
            session.closed = True
        return

    # 3. Ignore trailing ACKs after both FINs are seen
    if session.closed:
        return
    # If the session is marked to be ignored (non TLS or whitelisted) we just update the last timestamp for proper timeout handling but skip all the analysis
    if session.ignore:
        session.last_ts = ts
        return


    # --- 2. PAYLOAD TIMING CHECKS ---
    if 'P' in tcp_layer.flags:
        if session.last_psh_ts is not None:
            delta = ts - session.last_psh_ts
            if delta >= config['min_delta']:
                session.deltas.append(delta)
                
                # if we got enough deltas, we can start evaluating the beaconing pattern
                if len(session.deltas) == config['min_beacon_count']:
                    mean_delta = sum(session.deltas) / len(session.deltas)
                    #Prevents division by zero, calculates std_dev and jitter percentage for the window of deltas
                    if mean_delta > 0:
                        variance = sum((d - mean_delta)**2 for d in session.deltas) / len(session.deltas)
                        std_dev = math.sqrt(variance)
                        jitter_percent = (std_dev / mean_delta) * 100
                        
                        # If this windows has low enough jitter, we consider it a potential beaconing pattern and try to cluster it
                        if jitter_percent <= config['jitter']:
                            clustering_tolerance = config['jitter'] / 100.0 
                            best_cluster = None
                            min_diff_ratio = float('inf')
                            
                            for cluster in session.discovered_clusters:
                                diff_ratio = abs(mean_delta - cluster['center']) / cluster['center']
                                if diff_ratio <= clustering_tolerance:
                                    if diff_ratio < min_diff_ratio:
                                        min_diff_ratio = diff_ratio
                                        best_cluster = cluster
                                        
                            if best_cluster:
                                best_cluster['count'] += 1
                                best_cluster['jitters'].append(jitter_percent)
                                best_cluster['all_means'].append(mean_delta)
                                best_cluster['center'] = sum(best_cluster['all_means']) / len(best_cluster['all_means'])
                            else:
                                session.discovered_clusters.append({
                                    'center': mean_delta,
                                    'count': 1,
                                    'jitters': [jitter_percent],
                                    'all_means': [mean_delta]
                                })
                                
        session.last_psh_ts = ts



    # --- 4. DPI LAZY & EARLY EXIT ---
    # If the handhake has alredy been inspected or there has already been 15 packets without it showing up we skip DPI
    if session.inspect_payload and packet.haslayer("Raw"):
        if session.packet_count > 15:
            session.inspect_payload = False
            if not config['all_tcp']:
                session.ignore = True
            return
            
        payload = bytes(packet["Raw"])
        
        # TLS Singnature: 0x16 (Handshake) + 0x03 (TLS 1.x)
        if len(payload) > 5 and payload[0] == 0x16 and payload[1] == 0x03:
            try:
                handshake_type = payload[5]
                
                # CLIENT HELLO ANALYSIS
                if handshake_type == 0x01 and not session.client_hello_seen:
                    tls_pkt = TLS(payload)
                    if tls_pkt.haslayer(TLSClientHello):
                        session.client_hello_seen = True

                        # Grabs client hello layer
                        client_hello = tls_pkt[TLSClientHello]
                        session.inspect_payload = False

                        # Verifies the presence of extensions
                        if hasattr(client_hello, 'ext') and client_hello.ext:
                            for ext in client_hello.ext:
                                # Grabs thr raw type of the extension, if it's not present we put 'N/A'
                                ext_type = getattr(ext, 'type', 'N/A')

                                # If it's the right extension we go on looking for the SNI extension (ID 0)
                                if ext_type == 0 or isinstance(ext, TLS_Ext_ServerName):
                                    if hasattr(ext, 'servernames') and ext.servernames:
                                        raw_sni = ext.servernames[0].servername
                                        session.sni = raw_sni.decode('utf-8', errors='ignore') if isinstance(raw_sni, bytes) else str(raw_sni)
                                        break
                                    else:
                                        print(f"{C_WARN}[WARNING]{C_RESET} Something went wrong extracting an SNI")
                            
                        #Checks if SNI is to be ignored, if it has been found
                        if whitelist and session.sni:
                            if get_target_info(session.sni) in whitelist:
                                session.ignore = True
                                return

            except Exception:
                pass # Malformed payload gets skipped

# Garbage collection of sessions that didn't properly close with FIN/RST, based on inactivity timeout
def sweep_timeouts(stats, current_ts, timeout_sec):
    """Removes sessions that have been inactive for longer than the timeout and moves them to completed sessions."""
    # Grabs all the keys of sessions that should be removed based on inactivity 
    keys_to_remove = [k for k, v in stats.active_sessions.items() if (current_ts - v.last_ts) > timeout_sec]
    for key in keys_to_remove:
        session = stats.active_sessions.pop(key)
        
        # If it was an ignored session we dont add it to completed sessions for further analysis
        if not session.ignore:
            stats.completed_sessions.append((key, session))

def calculate_flow_anomalies(stats, config):
    """Calculates flow patterns in search of beaconing"""
    print(f"\n{C_INFO}[*] Behaviour analysis in progress...{C_RESET}")
    found_any = False

    for flow_key, session in stats.completed_sessions:
        ep1, ep2 = flow_key
        ip1 = ep1.rsplit(':', 1)[0] #rsplit to properly handle IPv6
        ip2 = ep2.rsplit(':', 1)[0]

        # --- 1. Session duration control ---
        if session.duration > config['max_duration']:
            print("\n\n") #Separation needed to make the output more readable in case of long sessions with beaconing patterns
            print(f"{C_WARN}LONG SESSION: {ep1} <-> {ep2} Active for {session.duration/60:.1f} min!{C_RESET}")
            stats.suspicious_ips[ip1] += 500
            stats.suspicious_ips[ip2] += 500
            found_any = True

        # --- 2. Window clustering output for each session ---
        if session.discovered_clusters:
            found_any = True
            sni_str = session.sni if session.sni else "N/A"
            
            print(f"\n{C_CRIT}POSSIBLE BEACONING{C_RESET}")
            print(f" {C_WARN}Session between:{C_RESET} {ep1} <-> {ep2} (SNI: {sni_str})")
            print(f" {C_WARN}Beaconing profiles:{C_RESET}")
            
            # Ordering clusters for sleep time
            session.discovered_clusters.sort(key=lambda x: x['center'])
            
            for cluster in session.discovered_clusters:
                freq = int(round(cluster['center']))
                avg_jitter = sum(cluster['jitters']) / len(cluster['jitters'])
                print(f"   ► Pattern at ~{freq} sec | Windows: {cluster['count']} | Average Jitter: {avg_jitter:.2f}%")
                
                # If there's a slow pattern it gets more points per window, as there will be less of them
                if freq < 20 :
                    score = (20 *cluster['count'])
                elif 20 <= freq < 3600:
                    score = (50 *cluster['count'])
                else:
                    score = (100 * cluster['count'])
                stats.suspicious_ips[ip1] += score
                stats.suspicious_ips[ip2] += score

    if not found_any:
        print(f"{C_INFO}[+] No C2 behaviour detected.{C_RESET}")

def print_report(stats):
    """Prints final leaderboard of most suspicious ip's."""
    print(f"\n{C_INFO}================= SUSPICIOUS HOSTS REPORT ================={C_RESET}")
    if not stats.suspicious_ips:
        print(f"{C_INFO}No IP surpassed anomaly thresholds.{C_RESET}")
    else:
        print(f"{C_INFO}{'IP ADDRESS':<20} | {'ANOMALY SCORE':<15}{C_RESET}")
        print("-" * 38)
        
        for ip, score in stats.suspicious_ips.most_common():
            if score >= 30:
                row_color = C_CRIT      
            elif score >= 15:
                row_color = C_WARN      
            else:
                row_color = C_ANOMALY   
                
            print(f"{row_color}{ip:<20} | {score:<15}{C_RESET}")
    print(f"{C_INFO}==========================================================={C_RESET}\n")

def analyze_flows_pcap(pcap_file, config):
    """Main function to analyze the PCAP file, parses packets, extracts sessions, and performs post-analysis for beaconing patterns calling the other functions."""
    print(f"{C_INFO}[INFO]{C_RESET} Starting analysis on: {pcap_file}...")
    stats = HTTPSStats()

    try:
        with PcapReader(pcap_file) as packets:
            for packet in packets:
                stats.total_packets += 1
                
                if packet.haslayer(TCP):
                    process_packet(packet, stats, config)
                
                # Garbage collection of closed sessions without FIN or RST
                if stats.total_packets % 10000 == 0:
                    current_ts = float(packet.time)
                    sweep_timeouts(stats, current_ts, config['timeout'])
                    print(f"\r[~] {C_INFO}Processed {stats.total_packets} pkts | Active sessions: {len(stats.active_sessions)}{C_RESET}", end="", flush=True)

    except Exception as e:
        print(f"\n{C_CRIT}[ERROR]{C_RESET} Error while reading the PCAP: {e}")

    # Forced close of sessions at end file
    sweep_timeouts(stats, float('inf'), 0)
    print(f"\r[+] Analysis has finished. {stats.total_packets} packets read. Total sessions: {len(stats.completed_sessions)}       \n")

    calculate_flow_anomalies(stats, config)
    print_report(stats)

def main():
    """Main function, parses command line arguments, validates the PCAP file, sets up the whitelist, and starts the analysis."""
    print_banner()
    parser = argparse.ArgumentParser(description="HTTPS Auditor - Flow-Based Tunnel Hunter (Scapy Lazy DPI)")
    parser.add_argument("-f", "--file", required=True, help="PCAP file path (.pcap or .pcapng)", type=str)
    parser.add_argument("-to", "--timeout", type=int, default=300, help="Max inactivity before calling a session inactive(default: 300)")
    parser.add_argument("-wl", "--whitelist", help="Path to a text file containing domains/IPs to ignore (one per line)", type=str, default=None)
    

    parser.add_argument("-jt", "--jitter", type=float, default=20.0, help="Maximum jitter percentage to flag posssible beaconing (default: 20.0)")
    parser.add_argument("-bc", "--min_beacon_count", type=int, default=10, help="Minimum number of packets to consider a flow for C2 analysis (default: 10)")
    parser.add_argument("-maxd", "--max_duration", type=int, default=3600, help="Maximum duration of a connection in seconds before flagging (default: 3600)")
    parser.add_argument("-mdlt",  "--min_delta", type=float, default=1, help="Minimum time delta between packets to consider them for C2 analysis")
    parser.add_argument("-a",  "--all_tcp", action= "store_true", help="Analyzes all tcp traffic not on known ports, not just TLS")

    args = parser.parse_args()

    config = vars(args)
    if not os.path.isfile(config['file']) or not config['file'].lower().endswith(('.pcap', '.pcapng')):
        print(f"{C_CRIT}[ERROR]{C_RESET} File not found or invalid format: {config['file']}")
        sys.exit(1)
    set_whitelist(config)
        
    analyze_flows_pcap(config['file'], config)

if __name__ == "__main__":
    main()