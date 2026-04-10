import argparse
import sys
import os
import math
from collections import Counter
import tldextract #Used to separate subdomains correctly
import functools
from scapy.all import PcapReader, DNS, DNSQR, DNSRR, UDP, IP, IPv6

# --- GLOBAL CONSTANTS FOR OPTIMIZATION ---
HEX_CHARS = set("0123456789abcdefABCDEF")
BASE32_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz234567=-_")
#Define the TLD extractor once globally to avoid re-initialization on every packet, which is costly.
extractor = tldextract.TLDExtract()

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    GREEN = Fore.GREEN
    RED = Fore.RED
    YELLOW = Fore.YELLOW
    RESET = Style.RESET_ALL
except ImportError:
    GREEN = RED = YELLOW = RESET = ""

# --- DATA STRUCTURES ---
class DNSQStats:
    """Class to keep track of all counters and metrics for queries."""
    def __init__(self):
        self.total_queries = 0
        self.long_queries = 0
        self.high_entropy = 0
        self.many_subdomains = 0
        self.txt = 0
        self.null = 0
        self.cname = 0
        self.c2_ips = Counter()
        self.exfil_ips = Counter()

        self.suspicious_domains = Counter()
        self.ip_domain_pairs = Counter()

class DNSRStats:
    """Class to keep track of all counters and metrics related to DNS responses."""
    def __init__(self):
        self.total_responses = 0
        self.null_responses = 0
        self.txt_responses = 0

        self.suspicious_dst_ips = Counter()

def print_banner():
    """Prints the ASCII art banner and tool name."""
    banner = f"""{GREEN}
  _____  _   _  _____                     _ _ _             
 |  __ \\| \\ | |/ ____|     /\\            | (_) |            
 | |  | |  \\| | (___      /  \\  _   _  __| |_| |_ ___  _ __ 
 | |  | | . ` |\\___ \\    / /\\ \\| | | |/ _` | | __/ _ \\| '__|
 | |__| | |\\  |____) |  / ____ \\ |_| | (_| | | || (_) | |   
 |_____/|_| \\_|_____/  /_/    \\_\\__,_|\\__,_|_|\\__\\___/|_|   
                                                                  
            -- DNS Tunneling & Exfiltration Auditor --
                   -- V 2.0 by Fabio Zolin --                   
    {RESET}"""
    print(banner)

# --- UTILITY FUNCTIONS ---

def load_whitelist(filepath):
    """Reads a whitelist of domains from a text file into a fast-lookup set."""
    if not filepath:
        return set() 
        
    if not os.path.isfile(filepath):
        print(f"[{YELLOW}WARNING{RESET}] Whitelist file '{filepath}' not found. Proceeding without it.")
        return set()

    whitelist = set()
    try:
        with open(filepath, 'r') as f:
            for line in f:
                raw_domain = line.strip().lower()
                
                if raw_domain and not raw_domain.startswith('#'):
                    ext = extractor(raw_domain)
                    # Add only the core organization name to the set
                    if ext.domain:
                        whitelist.add(ext.domain)
                        
        print(f"[{GREEN}INFO{RESET}] Successfully loaded {len(whitelist)} trusted domains from {filepath}.")
    except Exception as e:
        print(f"[{RED}ERROR{RESET}] Failed to read whitelist: {e}")
        
    return whitelist


@functools.lru_cache(maxsize=10000)
def get_domain_info(domain):
    """
    The 'Master Cache': Runs tldextract once and returns 
    all components needed for whitelisting, entropy, and subdomain counting.
    """
    ext = extractor(domain)
    subdomains = ext.subdomain
    
    # Calculate the true number of subdomains.
    actual_subdomain_count = subdomains.count(".") + 1 if subdomains else 0
    
    # Remove dots to get the raw payload for entropy analysis
    clean_payload = subdomains.replace(".", "") 
    
    return {
        'org_name': ext.domain,                   # e.g., "microsoft" (Used for Whitelisting)
        'clean_payload': clean_payload,           # e.g., "chunk123"  (Used for Entropy)
        'subdomain_count': actual_subdomain_count, # True architecture count
        'root_full': f"{ext.domain}.{ext.suffix}" # e.g., "microsoft.co.uk" (Used for Stats)
    }


def analyze_entropy_smart(text, config):
    """
    Entropy calculation based on Shannon's formula.
    """
    if not text:
        return False, 0.0
        
    # 1. Entropy Calculation (Shannon's Entropy)
    entropy = 0
    char_counts = Counter(text)
    total_chars = len(text)
    for count in char_counts.values():
        probability = count / total_chars
        entropy -= probability * math.log2(probability)
        
    # 2. Alphabet detection using Global Sets
    chars_in_text = set(text)
    
    # 3. Apply pre-calculated thresholds
    if chars_in_text.issubset(HEX_CHARS):
        dynamic_threshold = config['thresh_hex']
        
    elif chars_in_text.issubset(BASE32_CHARS):
        dynamic_threshold = config['entropy']
        
    else:
        dynamic_threshold = config['thresh_complex']
        
    return (entropy >= dynamic_threshold), entropy


# --- CORE ARCHITECTURE ---

def print_analysis_report(query_stats, response_stats):
    """Handles exclusively the formatting and printing of the final report to the console."""
    print(f"\n[{GREEN}INFO{RESET}] Analysis Complete.")
    print(f"Total DNS Queries Analyzed: {query_stats.total_queries}")
    print(f"Total DNS Responses Analyzed: {response_stats.total_responses}")
    
    # --- Queries stats ---
    if query_stats.total_queries > 0:
        long_pct = (query_stats.long_queries / query_stats.total_queries) * 100
        entropy_pct = (query_stats.high_entropy / query_stats.total_queries) * 100
        subdomain_pct = (query_stats.many_subdomains / query_stats.total_queries) * 100
        txt_pct = (query_stats.txt / query_stats.total_queries) * 100
        null_pct = (query_stats.null / query_stats.total_queries) * 100
        cname_pct = (query_stats.cname / query_stats.total_queries) * 100
        
        print(f"\n--- General Anomalies ---")
        print(f" - Long Queries:      {query_stats.long_queries} ({long_pct:.2f}%)")
        print(f" - High Entropy:      {query_stats.high_entropy} ({entropy_pct:.2f}%)")
        print(f" - Many Subdomains:   {query_stats.many_subdomains} ({subdomain_pct:.2f}%)")
        
        print(f"\n--- Query Record Types (Outbound) ---")
        print(f" - TXT Queries:       {query_stats.txt} ({txt_pct:.2f}%)")
        print(f" - NULL Queries:      {query_stats.null} ({null_pct:.2f}%)")
        print(f" - CNAME Queries:     {query_stats.cname} ({cname_pct:.2f}%)")

    # --- Responses stats ---
    if response_stats.total_responses > 0:
        txt_r_pct = (response_stats.txt_responses / response_stats.total_responses) * 100
        null_r_pct = (response_stats.null_responses / response_stats.total_responses) * 100
        
        print(f"\n--- Response Record Types (Inbound / C2) ---")
        print(f" - TXT Responses:  {response_stats.txt_responses} ({txt_r_pct:.2f}%)")
        print(f" - NULL Responses: {response_stats.null_responses} ({null_r_pct:.2f}%)")

    # --- Top offenders ---
    if query_stats.c2_ips or query_stats.exfil_ips:
        print(f"\n--- Suspicious Hosts (Top Offenders) ---")
        
        if query_stats.c2_ips:
            print(f" [{YELLOW}C2 POLLING{RESET}] Top IPs requesting TXT records:")
            for ip, count in query_stats.c2_ips.most_common(5):
                print(f"   -> {ip}: {count} requests")
        
        if query_stats.exfil_ips:
            print(f" [{RED}DATA EXFILTRATION{RESET}] Top IPs triggering High Entropy or NULL records:")
            for ip, count in query_stats.exfil_ips.most_common(5):
                print(f"   -> {ip}: {count} alerts")

    if response_stats.suspicious_dst_ips:
        print(f"\n [{RED}C2 INFECTION{RESET}] Top Internal IPs receiving Suspicious Payloads:")
        for ip, count in response_stats.suspicious_dst_ips.most_common(5):
            print(f"   -> {ip}: {count} malicious responses received")

    if query_stats.suspicious_domains:
        print(f"\n--- Top Suspicious Root Domains ---")
        for domain, count in query_stats.suspicious_domains.most_common(5):
            print(f"   -> {domain}: flagged {count} times")

    if query_stats.ip_domain_pairs:
        print(f"\n--- Top Suspicious Connections (IP -> Domain) ---")
        for (ip, domain), count in query_stats.ip_domain_pairs.most_common(5):
            print(f"   -> [{ip}] queried [{domain}] {count} flagging times")
    

def process_dns_queries(packet, query_stats, config):
    """Core engine: evaluates a single packet query and updates the DNSQStats object."""
    # If it's not DNS, or if it IS DNS but it's a response (qr != 0), ignore it.
    if not packet.haslayer(DNS) or packet[DNS].qr != 0:
        return 
    
    try:
        if packet.haslayer(IP):
            src_ip = packet[IP].src
        elif packet.haslayer(IPv6):
            src_ip = packet[IPv6].src
        else:
            return # No IP layer found

        # Grab the very first query record attached to the DNS header
        current_query = packet[DNS].qd
        is_exfil = False
        is_c2 = False
        # Traverse the linked list of queries using a while loop
        # Protects against malformed 'qdcount' headers and handles multiple queries
        while current_query:
            query_stats.total_queries += 1
            
            # Extract domain, convert to lowercase, and replace bad bytes safely
            looked_up_domain = current_query.qname.decode('utf-8', errors='replace').rstrip('.').lower()

            # --- THE MASTER CACHE ---
            domain_data = get_domain_info(looked_up_domain)

            # --- TLD-AWARE WHITELIST CHECK ---
            if config['whitelist'] and domain_data['org_name'] in config['whitelist']:
                # Advance pointer before skipping to prevent infinite loops
                current_query = current_query.payload
                if not isinstance(current_query, DNSQR):
                    break
                continue # Skip! It's a trusted core domain.

            qtype = current_query.qtype

            # Using a closure here to keep the code DRY. 
            def track_suspicious_domain():
                # We can use the pre-calculated root domain from the cache!
                root_domain = domain_data['root_full']
                query_stats.suspicious_domains[root_domain] += 1
                query_stats.ip_domain_pairs[(src_ip, root_domain)] += 1
            
            # Check 1: Length
            if len(looked_up_domain) > config['domain_length']:
                query_stats.long_queries += 1
                track_suspicious_domain()
                if config['very_verbose']:
                    print(f"[{YELLOW}WARNING{RESET}] Long Query from {src_ip}: {looked_up_domain} ({len(looked_up_domain)} chars)")

            # Check 2: Smart Entropy (Outbound) - Uses the cached clean payload!
            is_suspicious_entropy, entropy_score = analyze_entropy_smart(domain_data['clean_payload'], config)
            
            if is_suspicious_entropy:
                query_stats.high_entropy += 1
                track_suspicious_domain()
                if not is_exfil:
                    query_stats.exfil_ips[src_ip] += 1
                    is_exfil = True
                if config['verbose']:
                    print(f"[{RED}ALERT{RESET}] High Entropy ({entropy_score:.2f}) from {src_ip}: {looked_up_domain}")

            # Check 3: Subdomain Number - Uses the mathematically accurate cached count!
            if domain_data['subdomain_count'] >= config['subdomain_number']:
                query_stats.many_subdomains += 1
                if config['very_verbose']:
                    print(f"[{YELLOW}WARNING{RESET}] Many Subdomains from {src_ip}: {looked_up_domain} ({domain_data['subdomain_count']} subdomains)")

            # Check 4: Specific Record Types
            if qtype == 16: # TXT
                query_stats.txt += 1
                if not is_c2:
                    query_stats.c2_ips[src_ip] += 1
                    is_c2 = True
                if config['show_txt'] or config['very_verbose']:
                    print(f"[{YELLOW}WARNING{RESET}] TXT Request from {src_ip}: {looked_up_domain}")

            elif qtype == 10: # NULL
                query_stats.null += 1
                track_suspicious_domain()
                if not is_exfil:
                    query_stats.exfil_ips[src_ip] += 1
                    is_exfil = True
                if config['show_null'] or config['verbose']:
                    print(f"[{RED}CRITICAL{RESET}] NULL Request from {src_ip}: {looked_up_domain}")

            elif qtype == 5: # CNAME
                query_stats.cname += 1
                if config['show_cname'] or config['very_verbose']:
                    print(f"[{YELLOW}WARNING{RESET}] CNAME Request from {src_ip}: {looked_up_domain}")

            # --- MOVE TO THE NEXT QUERY LAYER ---
            current_query = current_query.payload
            
            if not isinstance(current_query, DNSQR):
                break

    except (IndexError, AttributeError):
        pass

def process_dns_responses(packet, response_stats, config):
    """Analyzes DNSRR records to find possible C2 traffic."""
    if not packet.haslayer(DNS) or packet[DNS].qr != 1: 
        return
        
    try:
        if packet.haslayer(IP):
            dst_ip = packet[IP].dst
        elif packet.haslayer(IPv6):
            dst_ip = packet[IPv6].dst
        else:
            return # No IP layer found

# Iterate through Answer (an), Authority (ns), and Additional (ar) sections
        for dns_section in [packet[DNS].an, packet[DNS].ns, packet[DNS].ar]:
            current_answer = dns_section

            # Safer check: ensures we are actually looking at a DNS Resource Record
            while isinstance(current_answer, DNSRR):
                record_type = current_answer.type
                response_stats.total_responses += 1
                
                # We wrap the decoding in a try/except just in case a malformed 
                # stealth record is missing the rrname attribute
                try:
                    domain = current_answer.rrname.decode('utf-8', errors='replace').rstrip('.').lower()
                except AttributeError:
                    current_answer = current_answer.payload
                    continue

                # --- THE MASTER CACHE ---
                domain_data = get_domain_info(domain)

                # --- TLD-AWARE WHITELIST CHECK ---
                if config['whitelist'] and domain_data['org_name'] in config['whitelist']:
                    current_answer = current_answer.payload
                    continue 

                payload = current_answer.rdata
                    
                # --- TXT Records (Type 16) ---
                if record_type == 16:
                    response_stats.txt_responses += 1
                    
                    # Applying the decoding bug fix mentioned earlier!
                    if isinstance(payload, list):
                        payload_text = "".join([b.decode('utf-8', errors='ignore') if isinstance(b, bytes) else str(b) for b in payload])
                    elif isinstance(payload, bytes):
                        payload_text = payload.decode('utf-8', errors='ignore')
                    else:
                        payload_text = str(payload)
                    
                    is_suspicious_entropy, txt_entropy = analyze_entropy_smart(payload_text, config)
                    if is_suspicious_entropy:
                        if config['verbose'] or config['show_txt']:
                            print(f"[{RED}CRITICAL C2 PAYLOAD{RESET}] High Entropy TXT Response({txt_entropy:.2f}) from {domain} to {dst_ip}: \nPayload: {payload_text}")
                        response_stats.suspicious_dst_ips[dst_ip] += 1

                # --- NULL Records (Type 10) ---
                elif record_type == 10:
                    response_stats.null_responses += 1
                    payload_length = len(payload) if payload else 0
                    
                    if config['verbose'] or config['show_null']:
                        print(f"[{RED}CRITICAL C2{RESET}] NULL Response from {domain} to {dst_ip}! \nInbound binary payload: {payload_length} bytes")
                    response_stats.suspicious_dst_ips[dst_ip] += 1
                    
                # --- MOVE TO THE NEXT LAYER ---
                current_answer = current_answer.payload
    except (IndexError, AttributeError):
        pass


def analyze_pcap(pcap_file, config):
    """Orchestrator: validates the file and iterates over the packets."""
    if not os.path.isfile(pcap_file):
        print(f"[{RED}ERROR{RESET}] The file '{pcap_file}' doesn't exist or the specified path is wrong.")
        sys.exit(1)

    print(f"[{GREEN}INFO{RESET}] Starting file analysis: {pcap_file}...")
    print(f"[{YELLOW}WAIT{RESET}] Building parsing module and analyzing packets (this may take a while)...")
    
    query_stats = DNSQStats()
    response_stats = DNSRStats()
    
    with PcapReader(pcap_file) as packets:
        for packet in packets:
            process_dns_queries(packet, query_stats, config)
            process_dns_responses(packet, response_stats, config)
            
    print_analysis_report(query_stats, response_stats)


def main():
    print_banner()
    # Setting up the arguments.
    parser = argparse.ArgumentParser(description="PCAP analyzer to detect DNS tunneling and data exfiltration.")
    parser.add_argument("-f", "--file", help="Path to the .pcap file to analyze", required=True)
    parser.add_argument("-dl", "--domain_length", help="Specifies the max domain length before flagging", default=50, type = int)
    parser.add_argument("-et", "--entropy_threshold", help="Specifies entropy thresholds, this is a sensibility setting, max: 5 flags only perfect enthropy, 0 flags everything (default: 4.0)", default=4, type=float)
    parser.add_argument("-sn", "--subdomain_number", help="Specifies the max number of subdomains before flagging (default: 5)", default= 5, type= int)
    parser.add_argument("-wl", "--whitelist", help="Path to a .txt file containing trusted root domains (one per line)")

    parser.add_argument("-t", "--txt", help="Display all TXT DNS requests in the output", action="store_true")
    parser.add_argument("-n", "--null", help="Display all NULL DNS requests in the output (Highly suspicious)", action="store_true")
    parser.add_argument("-c", "--cname", help="Display all CNAME DNS requests in the output", action="store_true")
    parser.add_argument("-v", "--verbose", help="Enable verbose mode (displays Critical and Alert individual records)", action="store_true")
    parser.add_argument("-vv", "--very_verbose", help="Enable very verbose mode (displays all warnings and suspicious records)", action="store_true")
    
    args = parser.parse_args()
    
    # Parse the base threshold once
    base_et = args.entropy_threshold
    strictness_ratio = base_et / 5.0

    # All the arguments in one single variable
    config = {
        'domain_length': args.domain_length,
        'subdomain_number': args.subdomain_number,
        
        # Pre-calculated Entropy Thresholds
        'thresh_hex': 4.0 * strictness_ratio,
        'entropy': base_et, #base entropy threshold is the one for base 32
        'thresh_complex': 6.0 * strictness_ratio,
        
        'show_txt': args.txt,
        'show_null': args.null,
        'show_cname': args.cname,
        'verbose': True if args.very_verbose else args.verbose,
        'very_verbose': args.very_verbose,
        
        # Load the whitelist into the config
        'whitelist': load_whitelist(args.whitelist)
    }

    if config['domain_length'] < 20:
        print(f"[{YELLOW}WARNING{RESET}] The max domain length threshold is low; expect a high number of false positives.")

    if config['entropy'] < 3:
        print(f"[{YELLOW}WARNING{RESET}] The max entropy setting is low, expect a high number of false positives.")

    analyze_pcap(args.file, config)

if __name__ == "__main__":
    main()