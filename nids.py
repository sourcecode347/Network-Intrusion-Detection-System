from scapy.all import sniff, IP, TCP, UDP, ICMP
import time
import datetime
import threading
from collections import defaultdict
import logging

# ====================== CONFIGURATION ======================
INTERFACE = "eth0"          # Change to your interface: wlan0, Wi-Fi, "Ethernet", etc.
LOG_FILE = "nids_alerts.log"
THRESHOLD_SYN_FLOOD = 50    # SYN packets from same IP in 5 seconds
THRESHOLD_PORT_SCAN = 20    # Different ports in short time
MAX_PACKET_SIZE = 1500      # Alert for packets larger than this (normal MTU is ~1500)

# ====================== LOGGING ======================
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.WARNING,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# ====================== STATE TRACKING ======================
ip_syn_count = defaultdict(lambda: {"count": 0, "time": time.time()})
ip_ports = defaultdict(set)          # For port scan detection
packet_sizes = defaultdict(list)     # For repetitive/flood traffic detection

lock = threading.Lock()

def log_alert(alert_type, src_ip, details):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    message = f"[{timestamp}] ALERT: {alert_type} | SRC: {src_ip} | {details}"
    print(f"\033[91m{message}\033[0m")  # Red color in console
    logging.warning(message)

# ====================== PACKET ANALYZER ======================
def packet_callback(packet):
    if IP not in packet:
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    pkt_size = len(packet)
    current_time = time.time()

    with lock:
        # 1. Large / Suspicious Packet Detection
        if pkt_size > MAX_PACKET_SIZE:
            log_alert("LARGE PACKET", src_ip, f"Size: {pkt_size} bytes")

        # 2. SYN Flood Detection
        if TCP in packet and packet[TCP].flags == "S":  # SYN flag only
            data = ip_syn_count[src_ip]
            if current_time - data["time"] < 5:   # Within 5 seconds
                data["count"] += 1
                if data["count"] > THRESHOLD_SYN_FLOOD:
                    log_alert("SYN FLOOD", src_ip, f"{data['count']} SYN packets")
            else:
                data["count"] = 1
                data["time"] = current_time

        # 3. Port Scan Detection
        if TCP in packet:
            dport = packet[TCP].dport
            ip_ports[src_ip].add(dport)
            if len(ip_ports[src_ip]) > THRESHOLD_PORT_SCAN:
                log_alert("PORT SCAN", src_ip, f"{len(ip_ports[src_ip])} different ports")

        # 4. Repetitive / Flood Traffic Detection
        packet_sizes[src_ip].append(pkt_size)
        if len(packet_sizes[src_ip]) > 100:
            sizes = packet_sizes[src_ip][-50:]
            if len(set(sizes)) <= 3:   # Very few different packet sizes
                log_alert("REPETITIVE FLOOD", src_ip, "Same packet sizes detected")

        # 5. ICMP Flood / Large Ping Detection
        if ICMP in packet and pkt_size > 1000:
            log_alert("ICMP FLOOD / LARGE PING", src_ip, f"Size: {pkt_size}")

# ====================== MAIN FUNCTION ======================
def start_nids():
    print(f"Network Intrusion Detection System started on interface: {INTERFACE}")
    print("Monitoring for: SYN Flood, Port Scan, Large Packets, Flood attacks...\n")
    print("Press Ctrl+C to stop\n")

    try:
        sniff(iface=INTERFACE,
              prn=packet_callback,
              store=False,          # Do not store packets in memory
              filter="ip")          # Capture only IP packets
    except KeyboardInterrupt:
        print("\n\n🛑 NIDS stopped.")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    # Background thread for periodic cleanup
    def cleanup_thread():
        while True:
            time.sleep(60)
            with lock:
                # Remove old entries
                for ip in list(ip_syn_count.keys()):
                    if time.time() - ip_syn_count[ip]["time"] > 30:
                        del ip_syn_count[ip]
                for ip in list(ip_ports.keys()):
                    if len(ip_ports[ip]) > 0:
                        ip_ports[ip].clear()
    
    threading.Thread(target=cleanup_thread, daemon=True).start()
    
    start_nids()