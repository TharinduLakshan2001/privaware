"""
Process Anomaly Detection for PrivAware
"""
import psutil
import time
from ..core.alerts import send_alert

CRITICAL_PROCESSES = ["sshd", "systemd", "nginx"]  # Add more as needed
KNOWN_PROCESSES = set()

class ProcessMonitor:
    def __init__(self):
        self.known = set(p.info['name'] for p in psutil.process_iter(['name']))

    def scan(self):
        current = set(p.info['name'] for p in psutil.process_iter(['name']))
        new = current - self.known
        gone = self.known - current
        for proc in new:
            send_alert(f"New process started: {proc}")
        for proc in gone:
            if proc in CRITICAL_PROCESSES:
                send_alert(f"Critical process stopped: {proc}")
        self.known = current

    def monitor(self, interval=10):
        while True:
            self.scan()
            time.sleep(interval)
