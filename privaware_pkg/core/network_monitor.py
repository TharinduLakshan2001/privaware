"""
Network Intrusion Detection for PrivAware
"""
import psutil
import socket
import time
from ..core.alerts import send_alert

BLACKLISTED_IPS = set()  # Add known bad IPs here

class NetworkMonitor:
    def __init__(self):
        self.known_ports = set()

    def scan_ports(self):
        conns = psutil.net_connections()
        open_ports = set(conn.laddr.port for conn in conns if conn.status == 'LISTEN')
        new_ports = open_ports - self.known_ports
        if new_ports:
            send_alert(f"New listening ports detected: {new_ports}")
        self.known_ports = open_ports

    def scan_connections(self):
        conns = psutil.net_connections()
        for conn in conns:
            if conn.raddr and conn.raddr.ip in BLACKLISTED_IPS:
                send_alert(f"Connection to blacklisted IP: {conn.raddr.ip}:{conn.raddr.port}")

    def monitor(self, interval=10):
        while True:
            self.scan_ports()
            self.scan_connections()
            time.sleep(interval)
