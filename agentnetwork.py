import os
import sys
import time
import threading
from collections import defaultdict
import numpy as np
from sklearn.ensemble import IsolationForest

# Ensure script is run with root permissions for packet sniffing
if os.geteuid() != 0:
    print("[-] CRITICAL: This agent must be run as root (sudo) to sniff network packets.")
    sys.exit(1)

# Import Scapy inside the check to avoid errors if missing
from scapy.all import sniff, IP, TCP, UDP, ICMP

# ==========================================
# 1. GLOBAL VARIABLES & DATABASE
# ==========================================
# Tracks stats per IP window: { ip: { 'ports': set(), 'syn_count': 0, 'total_packets': 0 } }
network_metrics = defaultdict(lambda: {'ports': set(), 'syn_count': 0, 'total_packets': 0})
lock = threading.Lock()

# ==========================================
# 2. AI MODEL TRAINING (BASELINE)
# ==========================================
# Features: [Unique_Ports_Hit, TCP_SYN_Count, Total_Packets_Sent]
print("[+] Initializing Machine Learning Engine...")
X_train = np.array([
    [1, 0, 10],   # Normal: 1 user, talking to 1 port (e.g., web traffic)
    [2, 1, 15],   # Normal: DNS lookup and HTTPS connection
    [1, 0, 5],    # Normal: Background connection ping
    [200, 150, 400], # Anomaly: Nmap SYN scan hitting hundreds of ports
    [50, 50, 100],   # Anomaly: Rapid brute force attempt / targeted scan
])

# Use IsolationForest to identify statistical outliers
ai_model = IsolationForest(contamination=0.1, random_state=42)
ai_model.fit(X_train)
print("[+] AI Model Ready and trained on network baseline anomalies.")


# ==========================================
# 3. THREAD 1: PACKET SNIFFER (DATA INGESTION)
# ==========================================
def packet_callback(packet):
    """
    Processes every packet traversing the local network interface in real-time.
    """
    if IP in packet:
        src_ip = packet[IP].src
        
        with lock:
            network_metrics[src_ip]['total_packets'] += 1
            
            # Track targeted TCP ports and look for SYN scans
            if TCP in packet:
                dst_port = packet[TCP].dport
                network_metrics[src_ip]['ports'].add(dst_port)
                
                # Check for TCP SYN flag (Nmap scan baseline signature)
                if packet[TCP].flags == 'S':
                    network_metrics[src_ip]['syn_count'] += 1
                    
            # Track targeted UDP ports
            elif UDP in packet:
                dst_port = packet[UDP].dport
                network_metrics[src_ip]['ports'].add(dst_port)


def start_sniffing():
    print("[+] Packet sniffing engine started on default interface...")
    # store=0 tells scapy to discard packets from memory immediately after processing
    sniff(prn=packet_callback, store=0)


# ==========================================
# 4. THREAD 2: AI ANALYZER & ALERT ENGINE
# ==========================================
def ai_analysis_loop(interval_sec=5):
    """
    Evaluates gathered network footprints every X seconds against the AI engine.
    """
    print(f"[+] AI Analysis engine running. Evaluation window: {interval_sec}s")
    while True:
        time.sleep(interval_sec)
        
        with lock:
            # Copy snapshot of current metrics and flush the global database for next window
            current_snapshot = dict(network_metrics)
            network_metrics.clear()
            
        for ip, stats in current_snapshot.items():
            unique_ports = len(stats['ports'])
            syn_packets = stats['syn_count']
            total_packets = stats['total_packets']
            
            # Ignore completely idle traffic to save processing resources
            if total_packets < 5:
                continue
                
            # Prepare format for AI inference
            features = np.array([[unique_ports, syn_packets, total_packets]])
            prediction = ai_model.predict(features)
            
            # -1 signifies an outlier or attack behavior identified by the ML algorithm
            if prediction == -1:
                print(f"\n[!!!] NETWORK AI ALERT [!!!]")
                print(f"Source IP Accountable : {ip}")
                print(f"Unique Ports Investigated: {unique_ports}")
                print(f"TCP SYN Packet Count : {syn_packets}")
                print(f"Total Traffic Volume : {total_packets} packets")
                print(f"Signature Diagnostic : High profile scan/brute-force vector confirmed.")
                print("-" * 60)


# ==========================================
# 5. EXECUTION ENTRY POINT
# ==========================================
if __name__ == "__main__":
    # Launch Sniffer Thread
    sniffer_thread = threading.Thread(target=start_sniffing, daemon=True)
    sniffer_thread.start()
    
    # Launch AI Evaluation Loop in the Main Thread
    try:
        ai_analysis_loop(interval_sec=5)
    except KeyboardInterrupt:
        print("\n[-] Shutting down AI security agent safely.")
        sys.exit(0)
