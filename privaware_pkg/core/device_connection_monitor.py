# privaware_pkg/core/device_connection_monitor.py
"""
Real-time monitoring for USB/storage device connections.
Sends alerts with device details and mount options.
"""

import subprocess
import threading
import time
import os
from datetime import datetime
from pathlib import Path

# Import for udev monitoring
try:
    import pyudev
except ImportError:
    pyudev = None
    print("Warning: 'pyudev' not found. Device connection monitoring will not work. Install with 'pip install pyudev'.")

# Import existing alerting mechanisms
try:
    # Assuming AlertSender is in core.alerts
    from .alerts import AlertSender 
except (ImportError, ValueError): # Handle relative import issues
    try:
        from core.alerts import AlertSender
    except ImportError:
        AlertSender = None
        print("Warning: Alert system (AlertSender) not available for device monitor.")

class DeviceConnectionMonitor:
    """
    Monitors for block device connection events and sends alerts.
    """
    def __init__(self, send_alerts=True):
        self.send_alerts = send_alerts
        self.alert_sender = AlertSender() if send_alerts and AlertSender else None
        self.running = False
        self.monitor_thread = None

        if not pyudev:
            raise ImportError("pyudev is required for device connection monitoring.")

        try:
            self.context = pyudev.Context()
            self.monitor = pyudev.Monitor.from_netlink(self.context)
            # Filter for block devices, specifically partitions which are likely storage
            self.monitor.filter_by(subsystem='block', device_type='partition')
        except Exception as e:
            print(f"Error initializing udev monitor: {e}")
            self.monitor = None

    def _get_device_info(self, device):
        """Extract detailed information about the connected device."""
        info = {
            'device_node': device.device_node,
            'device_name': device.sys_name,
            'vendor': device.get('ID_VENDOR', 'Unknown'),
            'model': device.get('ID_MODEL', 'Unknown'),
            'serial': device.get('ID_SERIAL_SHORT', device.get('ID_SERIAL', 'Unknown')),
            'fs_type': device.get('ID_FS_TYPE', 'Unknown/Unmounted'),
            'label': device.get('ID_FS_LABEL', 'No Label'),
            'uuid': device.get('ID_FS_UUID', 'No UUID'),
            'size': "Unknown",
            'bus': device.get('ID_BUS', 'Unknown')
        }
        
        # Try to get size using lsblk
        try:
            result = subprocess.run(
                ['lsblk', '-bdn', '--output', 'SIZE', device.device_node],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0 and result.stdout.strip():
                size_bytes = int(result.stdout.strip().split('\n')[0])
                # Convert bytes to human-readable
                for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
                    if size_bytes < 1024.0:
                        info['size'] = f"{size_bytes:.1f} {unit}"
                        break
                    size_bytes /= 1024.0
        except (subprocess.SubprocessError, ValueError, IndexError):
            pass # Keep 'Unknown' size

        # Check initial mount status (might not be mounted immediately)
        info['mount_point'] = self._get_mount_point(device.device_node)
        
        return info

    def _get_mount_point(self, device_node):
        """Get the current mount point of a device node."""
        try:
            result = subprocess.run(
                ['lsblk', '-dn', '--output', 'MOUNTPOINT', device_node],
                capture_output=True, text=True, timeout=5
            )
            mount_point = result.stdout.strip()
            return mount_point if mount_point else "Not Mounted"
        except (subprocess.SubprocessError, FileNotFoundError):
            return "Mount Status Unknown"

    def _get_current_user(self):
        """Attempt to get the current logged-in user."""
        try:
            # Method 1: Environment variable
            user = os.environ.get('USER')
            if user:
                return user
            # Method 2: Command
            result = subprocess.run(['logname'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                return result.stdout.strip()
        except (subprocess.SubprocessError, FileNotFoundError):
            pass
        return "Unknown User"

    def _send_device_alert(self, device_info):
        """Send system notification and email alert for device connection."""
        if not self.send_alerts:
            print(f"[Device Monitor] Device connected: {device_info}")
            return

        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        user = self._get_current_user()
        device_desc = f"{device_info['vendor']} {device_info['model']}"

        # --- System Alert (notify-send) ---
        try:
            title = "PrivAware: USB Device Connected"
            message_body = (
                f"Vendor: {device_info['vendor']}\n"
                f"Model: {device_info['model']}\n"
                f"Device: {device_info['device_node']}\n"
                f"Size: {device_info['size']}"
            )
            # Suggest mount command
            mount_cmd = f"udisksctl mount -b {device_info['device_node']}"
            message_footer = f"\nMount with: {mount_cmd}"
            
            # Basic notify-send (doesn't always support actions well across all DEs)
            # The user would typically click the notification and copy the command.
            subprocess.run(
                ['notify-send', title, message_body + message_footer],
                timeout=5, stderr=subprocess.DEVNULL
            )
        except Exception as e:
            # notify-send might not be available or fail
            pass

        # --- Email Alert ---
        if not self.alert_sender:
            return

        subject = f"PrivAware Alert: New USB Device Connected - {device_desc}"

        message_lines = [
            "🛡️ PRIVAWARE DEVICE CONNECTION ALERT",
            f"🕒 {timestamp}",
            f"👤 User: {user}",
            "",
            "A new USB device has been connected to the system:",
            "",
            f"Device Node:    {device_info['device_node']}",
            f"Device Name:    {device_info['device_name']}",
            f"Vendor:         {device_info['vendor']}",
            f"Model:          {device_info['model']}",
            f"Serial Number:  {device_info['serial']}",
            f"Size:           {device_info['size']}",
            f"Filesystem:     {device_info['fs_type']}",
            f"Label:          {device_info['label']}",
            f"UUID:           {device_info['uuid']}",
            f"Bus Type:       {device_info['bus']}",
            f"Mount Point:    {device_info['mount_point']}",
            "",
            "To mount this device:",
            "1. Open a terminal.",
            "2. Run the following command:",
            f"   {mount_cmd}",
            "   # This will mount it to /media/$USER/<Label_or_UUID>",
            "",
            "To mount to a specific location:",
            "1. Create a mount point: sudo mkdir -p /mnt/my_device",
            f"2. Mount the device:     sudo mount {device_info['device_node']} /mnt/my_device",
            "",
            "Exercise caution when accessing devices from unknown sources."
        ]
        message = "\n".join(message_lines)

        try:
            success = self.alert_sender.send_alert(subject, message)
            if success:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] 📧 Device connection alert sent for {device_desc}")
            else:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] ❌ Failed to send device connection alert for {device_desc}")
        except Exception as e:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] ❌ Error sending device connection alert: {e}")

    def _handle_device_event(self, device):
        """Callback function for udev events."""
        action = device.action
        if action == 'add':
            # Filter for USB devices primarily
            if device.get('ID_BUS') == 'usb':
                print(f"[Device Monitor] USB Device Added: {device.device_node}")
                device_info = self._get_device_info(device)
                self._send_device_alert(device_info)

    def _monitor_loop(self):
        """Main loop for monitoring udev events."""
        print("[Device Monitor] Starting real-time USB device connection monitoring...")
        print("[Device Monitor] Press Ctrl+C to stop.")
        try:
            # Use MonitorObserver for simplicity in a blocking loop
            observer = pyudev.MonitorObserver(self.monitor, callback=self._handle_device_event)
            observer.start()
            
            # Keep the thread alive
            while self.running:
                time.sleep(1)
                
        except KeyboardInterrupt:
            print("\n[Device Monitor] Stopping due to KeyboardInterrupt...")
        except Exception as e:
            print(f"[Device Monitor] Error in monitoring loop: {e}")
        finally:
            self.running = False
            print("[Device Monitor] Monitoring stopped.")

    def start_monitoring(self):
        """Start the device monitoring in a background thread."""
        if not self.monitor:
            print("[Device Monitor] Cannot start monitoring, udev not initialized.")
            return False
        if self.running:
            print("[Device Monitor] Already running.")
            return True

        self.running = True
        # Use daemon=True so the thread stops when the main program exits
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True) 
        self.monitor_thread.start()
        return True

    def stop_monitoring(self):
        """Stop the device monitoring."""
        if self.running:
            self.running = False
            if self.monitor_thread and self.monitor_thread.is_alive():
                # The thread sleeps, so it should stop quickly after self.running is False
                self.monitor_thread.join(timeout=2) # Wait max 2 seconds
            print("[Device Monitor] Monitoring stopped.")
        else:
            print("[Device Monitor] Not running.")

# --- Standalone execution for testing ---
if __name__ == "__main__":
    print("Testing DeviceConnectionMonitor...")
    try:
        monitor = DeviceConnectionMonitor(send_alerts=True)
        if monitor.start_monitoring():
            try:
                # Keep the main thread alive while the monitor runs
                # Use a simple loop or input() to wait
                input("Monitoring started. Press Enter to stop...\n")
            except KeyboardInterrupt:
                print("\nReceived interrupt in test mode.")
            finally:
                monitor.stop_monitoring()
        else:
            print("[Test] Failed to start monitor.")
    except ImportError as e:
        print(f"[Test] Import error: {e}")
