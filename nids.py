from scapy.all import sniff, IP, TCP, UDP, ICMP
import time
import datetime
import threading
from collections import defaultdict
import logging
import argparse
import subprocess
import os

# ====================== CONFIGURATION ======================
INTERFACE = "eth0"                    # ← Ελέγχξτε με: ip link show
LOG_FILE = "nids_alerts.log"
THRESHOLD_SYN_FLOOD = 50
THRESHOLD_PORT_SCAN = 20
MAX_PACKET_SIZE = 1500

BLOCK_DURATION = 300                  # Θα αλλάζει με --auto-block
BLOCKED_IPS = {}                      # ip: expiration_timestamp
BLOCK_LOCK = threading.Lock()

# ====================== LOGGING ======================
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.WARNING,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# ====================== STATE ======================
ip_syn_count = defaultdict(lambda: {"count": 0, "time": time.time()})
ip_ports = defaultdict(set)
packet_sizes = defaultdict(list)

lock = threading.Lock()

# ====================== BLOCK CHECK ======================
def is_blocked(ip: str) -> bool:
    """Return True only if IP is currently blocked"""
    with BLOCK_LOCK:
        if ip not in BLOCKED_IPS:
            return False
        
        if time.time() < BLOCKED_IPS[ip]:
            return True
        else:
            # Expired → remove from our dict
            BLOCKED_IPS.pop(ip, None)
            return False


# ====================== NFTABLES BLOCKING ======================
def block_ip(ip: str, duration: int = None):
    if duration is None:
        duration = BLOCK_DURATION

    if is_blocked(ip):
        return  # Already blocked

    expiration = time.time() + duration

    with BLOCK_LOCK:
        BLOCKED_IPS[ip] = expiration

    try:
        # Create nftables table and set (if not exists)
        subprocess.run(["nft", "add", "table", "inet", "nids"], check=False, capture_output=True)
        subprocess.run(["nft", "add", "set", "inet", "nids", "blocked_ips",
                       "{ type ipv4_addr; flags timeout; timeout 1h; }"], 
                       check=False, capture_output=True)

        # Add IP with timeout
        subprocess.run([
            "nft", "add", "element", "inet", "nids", "blocked_ips",
            f"{{ {ip} timeout {duration}s }}"
        ], check=True, capture_output=True)

        log_alert("AUTO BLOCK", ip, f"Blocked for {duration} seconds")
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] IP {ip} blocked for {duration} seconds")
    except Exception as e:
        print(f"Failed to block {ip}: {e}")


def cleanup_expired_blocks():
    """Periodic cleanup"""
    while True:
        time.sleep(15)
        with BLOCK_LOCK:
            current = time.time()
            expired = [ip for ip, exp in list(BLOCKED_IPS.items()) if current > exp]
            for ip in expired:
                BLOCKED_IPS.pop(ip, None)
                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                print(f"[{timestamp}] Block for {ip} has expired - monitoring resumed")


# ====================== ALERT ======================
def log_alert(alert_type, src_ip, details):
    if is_blocked(src_ip):
        return  # Skip everything for blocked IPs

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    message = f"[{timestamp}] ALERT: {alert_type} | SRC: {src_ip} | {details}"
    print(f"\033[91m{message}\033[0m")
    logging.warning(message)

    if alert_type in ["SYN FLOOD", "PORT SCAN", "REPETITIVE FLOOD", "ICMP FLOOD / LARGE PING"]:
        block_ip(src_ip)


# ====================== PACKET CALLBACK ======================
def packet_callback(packet):
    if IP not in packet:
        return

    src_ip = packet[IP].src

    if is_blocked(src_ip):
        return

    pkt_size = len(packet)
    current_time = time.time()

    with lock:
        if pkt_size > MAX_PACKET_SIZE:
            log_alert("LARGE PACKET", src_ip, f"Size: {pkt_size} bytes")

        if TCP in packet and packet[TCP].flags == "S":
            data = ip_syn_count[src_ip]
            if current_time - data["time"] < 5:
                data["count"] += 1
                if data["count"] > THRESHOLD_SYN_FLOOD:
                    log_alert("SYN FLOOD", src_ip, f"{data['count']} SYN packets")
            else:
                data["count"] = 1
                data["time"] = current_time

        if TCP in packet:
            dport = packet[TCP].dport
            ip_ports[src_ip].add(dport)
            if len(ip_ports[src_ip]) > THRESHOLD_PORT_SCAN:
                log_alert("PORT SCAN", src_ip, f"{len(ip_ports[src_ip])} different ports")

        packet_sizes[src_ip].append(pkt_size)
        if len(packet_sizes[src_ip]) > 100:
            sizes = packet_sizes[src_ip][-50:]
            if len(set(sizes)) <= 3:
                log_alert("REPETITIVE FLOOD", src_ip, "Same packet sizes detected")

        if ICMP in packet and pkt_size > 1000:
            log_alert("ICMP FLOOD / LARGE PING", src_ip, f"Size: {pkt_size}")


# ====================== MAIN ======================
def start_nids():
    print(f"Network Intrusion Detection System started on interface: {INTERFACE}")
    print(f"Auto-block duration: {BLOCK_DURATION} seconds")
    print("Press Ctrl+C to stop\n")

    try:
        sniff(iface=INTERFACE, prn=packet_callback, store=False)
    except KeyboardInterrupt:
        print("\n\n🛑 Stopping NIDS...")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        print("Cleaning up all blocks...")
        with BLOCK_LOCK:
            for ip in list(BLOCKED_IPS.keys()):
                BLOCKED_IPS.pop(ip, None)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Python NIDS with Auto-Block")
    parser.add_argument("--auto-block", type=int, default=300,
                        help="Block duration in seconds (default: 300)")
    args = parser.parse_args()

    BLOCK_DURATION = args.auto_block

    if os.geteuid() != 0:
        print("❌ Please run with sudo!")
        exit(1)

    threading.Thread(target=cleanup_expired_blocks, daemon=True).start()
    start_nids()