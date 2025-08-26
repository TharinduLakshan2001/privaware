"""
USB Device Monitoring for PrivAware
"""
import time
import os
from ..core.alerts import send_alert

class USBMonitor:
    def __init__(self):
        self.known = self.get_usb_devices()

    def get_usb_devices(self):
        # Linux: list /dev/disk/by-id/usb*
        return set([f for f in os.listdir('/dev/disk/by-id') if f.startswith('usb')])

    def scan(self):
        current = self.get_usb_devices()
        new = current - self.known
        gone = self.known - current
        for dev in new:
            send_alert(f"New USB device connected: {dev}")
        for dev in gone:
            send_alert(f"USB device removed: {dev}")
        self.known = current

    def monitor(self, interval=10):
        while True:
            self.scan()
            time.sleep(interval)
