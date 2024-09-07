from scapy.all import sniff, IP, TCP, UDP
import sqlite3
from colorama import Fore, Style
from datetime import datetime

conn = sqlite3.connect('ids_logs.db')
cursor = conn.cursor()
cursor.execute('''CREATE TABLE IF NOT EXISTS logs
                  (timestamp TEXT, alert_type TEXT, source_ip TEXT, dest_ip TEXT, protocol TEXT, description TEXT)''')

RULES = [
    {"name": "Port Scan Detected", "desc": "Multiple connections to different ports", "ports": [21, 22, 23, 80, 443], "trigger_count": 5},
    {"name": "SQL Injection Detected", "desc": "Possible SQL injection attempt", "signature": ["SELECT", "DROP", "INSERT", "UPDATE", "DELETE", "UNION"]}
]

active_connections = {}

def detect_suspicious_activity(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        payload = str(packet[TCP].payload)
        proto = "TCP"

        if ip_src not in active_connections:
            active_connections[ip_src] = set()
        active_connections[ip_src].add(packet[TCP].dport)
        if len(active_connections[ip_src]) > RULES[0]["trigger_count"]:
            alert("Port Scan Detected", ip_src, ip_dst, proto, RULES[0]["desc"])

        if any(sig in payload.upper() for sig in RULES[1]["signature"]):
            alert("SQL Injection Detected", ip_src, ip_dst, proto, RULES[1]["desc"])

def alert(alert_type, source_ip, dest_ip, protocol, description):
    print(f"{Fore.RED}[ALERT]{Style.RESET_ALL} {alert_type}: {description}")
    print(f"Source IP: {source_ip}, Destination IP: {dest_ip}, Protocol: {protocol}")

    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    cursor.execute("INSERT INTO logs (timestamp, alert_type, source_ip, dest_ip, protocol, description) VALUES (?, ?, ?, ?, ?, ?)",
                   (timestamp, alert_type, source_ip, dest_ip, protocol, description))
    conn.commit()

def packet_sniffer():
    print(f"{Fore.GREEN}[INFO]{Style.RESET_ALL} Sniffer started...")
    sniff(prn=detect_suspicious_activity, store=False)

if __name__ == "__main__":
    packet_sniffer()
