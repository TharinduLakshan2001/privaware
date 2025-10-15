# core/file_realtime_watch.py - Smart Security-Focused Monitoring (keeping original class names)
"""
File Real-Time Watcher: Intelligent security-focused monitoring.
Alerts only on user/security events, logs system activity discretely.
"""

import os
import time
import pwd
import psutil
import subprocess
from pathlib import Path
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from collections import defaultdict, deque
from typing import Dict
import threading
import sys

# Try to import alert system
try:
    from .alerts import AlertSender
except (ImportError, ValueError):
    # Fallback for direct execution or import issues
    try:
        from alerts import AlertSender
    except ImportError:
        # Create a mock alert sender if not available
        class AlertSender:
            def send_alert(self, subject, message):
                print(f"[MOCK ALERT] Subject: {subject}")
                print(f"[MOCK ALERT] Message: {message}")

class CoolFileEventMonitor(FileSystemEventHandler):  # Keep original class name
    """Smart file event handler with security-focused intelligent alerts."""
    
    def __init__(self, watch_paths=None, ignore_patterns=None):
        super().__init__()
        self.alert_sender = AlertSender()
        self.watch_paths = watch_paths or ["/home", "/tmp"]
        self.ignore_patterns = ignore_patterns or []
        self.running = True
        
        # Security-focused statistics tracking
        self.security_events = 0
        self.system_events = 0
        
        # Security events queue (for alerts)
        self.security_queue = deque(maxlen=20)
        
        # System events queue (for discrete logging)
        self.system_queue = deque(maxlen=50)
        
        # Process classification for security
        self.system_processes = {
            'systemd', 'dbus-daemon', 'cron', 'atd', 'rsyslogd', 'sshd',
            'NetworkManager', 'ModemManager', 'bluetoothd', 'cupsd',
            'lightdm', 'gdm', 'Xorg', 'gnome-shell', 'pulseaudio',
            'udevd', 'systemd-logind', 'accounts-daemon', 'colord',
            'packagekitd', 'polkitd', 'rtkit-daemon', 'snapd',
            'whoopsie', 'unattended-upgrades', 'apt', 'dpkg', 'ldconfig',
            'systemd-udevd', 'systemd-journald', 'systemd-timesyncd',
            'kernel', 'kworker', 'ksoftirqd', 'migration', 'rcu',
            'ld.so.cache', 'locale.alias', '.Xauthority'
        }
        
        # Security-relevant user processes
        self.security_processes = {
            'nano', 'vim', 'vi', 'gedit', 'code', 'subl', 'atom',
            'touch', 'mkdir', 'rm', 'cp', 'mv', 'python', 'python3',
            'bash', 'sh', 'zsh', 'konsole', 'gnome-terminal', 'xterm',
            'firefox', 'chrome', 'chromium', 'thunderbird', 'gedit',
            'libreoffice', 'mousepad', 'pluma', 'leafpad',
            # Security tools that might indicate suspicious activity
            'nmap', 'nc', 'netcat', 'ncat', 'wireshark', 'tcpdump',
            'john', 'hashcat', 'hydra', 'medusa', 'aircrack',
            'metasploit', 'msfconsole', 'sqlmap', 'nikto', 'dirb',
            'burpsuite', 'armitage', 'beef', 'ettercap', 'mitmproxy',
            'arping', 'hping', 'nbtscan', 'smbclient', 'enum4linux',
            'enumiax', 'ike-scan', 'nfsstat', 'onesixtyone', 'oscanner',
            'sctp_scan', 'sctpscan', 'sfuzz', 'sgn', 'smbenum',
            'smtp-user-enum', 'sslscan', 'sslyze', 'thc-ipv6',
            'tnscmd10g', 'whatweb', 'acccheck', 'ace', 'adminenum',
            'admsnmp', 'airflood', 'airsnare', 'airvent', 'alfsnort',
            'amap', 'amun', 'arachni', 'arpon', 'arptools', 'asleap',
            'automater', 'avet', 'backdoor-factory', 'bane', 'bed',
            'beef-xss', 'bing-ip2hosts', 'binproxy', 'binscan', 'bkhive',
            'blindelephant', 'bluesnarfer', 'braa', 'bruteforce-luks',
            'btscanner', 'bulk_extractor', 'cain', 'caldera', 'cap3',
            'catacomb', 'cdpsnarf', 'cisco-auditing-tool', 'cisco-global-exploiter',
            'cisco-ocs', 'cisco-torch', 'cisco-snmp-enum', 'climber',
            'cmed', 'cmospwd', 'cmseek', 'coalfire', 'cocoapods-deintegrate',
            'conglomerate', 'cookie-cadger', 'copy-router-config', 'cowpatty',
            'crackle', 'creddump', 'cupp', 'cymothoa', 'darkd0rk3r',
            'davtest', 'dbd', 'deblaze', 'dhcpig', 'dhcp-starvation',
            'dhcpoptinj', 'dirb', 'dirbuster', 'dmitry', 'dnmap',
            'dns2geoip', 'dnsdict', 'dnsenum', 'dnsmap', 'dnsrecon',
            'dnstracer', 'dnswalk', 'dotdotpwn', 'driftnet', 'dsss',
            'eapmd5pass', 'enum4linux', 'enumiax', 'fierce', 'firewalk',
            'fragroute', 'fragrouter', 'freeradius-wpe', 'giskismet',
            'gobuster', 'golismero', 'goofile', 'gpredict', 'groke',
            'grr', 'gwcheck', 'hamster-sidejack', 'hash-identifier',
            'hashcat', 'hashid', 'hexorbase', 'highlight', 'hping3',
            'httrack', 'intrace', 'ismtp', 'jdwp-shellifier', 'jigsaw',
            'joomscan', 'jsql-injection', 'kalibrate-rtl', 'kismet',
            'knock', 'laudanum', 'legion', 'lbd', 'lcrypt', 'lemon',
            'lynis', 'macchanger', 'maltego', 'maskprocessor', 'masscan',
            'medusa', 'mimikatz', 'miranda', 'mitm6', 'mitmproxy',
            'nab', 'nbtscan', 'ncat', 'ncrack', 'ndiff', 'nessus',
            'netdiscover', 'netmask', 'netsniff-ng', 'netstat', 'nikto',
            'nmap', 'ntop', 'ohrwurm', 'onesixtyone', 'openvas',
            'oscanner', 'osrframework', 'p0f', 'padbuster', 'parsero',
            'patator', 'pcapfix', 'pdf-parser', 'pdfid', 'pdgmail',
            'peepdf', 'pixiewps', 'powerfuzzer', 'powersploit',
            'protos-sip', 'proxytunnel', 'pwnat', 'pykek', 'python-geoip',
            'python-whois', 'qssl', 'radamsa', 'rainbowcrack',
            'recon-ng', 'regeorg', 'reglookup', 'regripper', 'rsmangler',
            'sakis3g', 'samdump2', 'sbd', 'sbrowse', 'scapy', 'scout',
            'sctpscan', 'sfuzz', 'sgn', 'smbenum', 'smbmap', 'smtp-user-enum',
            'sniffjoke', 'sparta', 'spiderfoot', 'sqlmap', 'sqlninja',
            'sqlsus', 'sslcaudit', 'ssldump', 'sslh', 'sslscan',
            'sslsniff', 'sslyze', 'stunnel4', 'swaks', 'thc-ipv6',
            'thc-pptp-bruter', 'theharvester', 'tlssled', 'tnscmd10g',
            'twofi', 'ucsniff', 'udptunnel', 'uniscan', 'urlcrazy',
            'valgrind', 'vane', 'various', 'voiphopper', 'w3af',
            'wafw00f', 'wcalc', 'weevely', 'wfuzz', 'whatweb',
            'wifi-honey', 'wifite', 'wol-e', 'yersinia', 'zaproxy',
            'zmap', 'zarp'
        }
        
        # Sensitive files that trigger security alerts
        self.sensitive_files = {
            '/etc/passwd', '/etc/shadow', '/etc/sudoers', '/etc/ssh/',
            '/root/.ssh/', '/home/', '/etc/cron', '/etc/at.allow',
            '/etc/at.deny', '/etc/crontab', '/etc/cron.d/',
            '/etc/cron.daily/', '/etc/cron.hourly/', '/etc/cron.monthly/',
            '/etc/cron.weekly/', '/etc/passwd-', '/etc/shadow-',
            '/etc/group', '/etc/group-', '/etc/gshadow', '/etc/gshadow-',
            '/etc/hosts', '/etc/resolv.conf', '/etc/network/', '/var/log/',
            '/root/.bash_history', '/root/.zsh_history', '/root/.viminfo',
            '/home/*/.bash_history', '/home/*/.zsh_history', '/home/*/.viminfo'
        }
        
        # Start the smart display thread
        self.display_thread = threading.Thread(target=self._smart_display, daemon=True)
        self.display_thread.start()
        
    def _smart_display(self):
        """Smart security-focused display with discrete system logging."""
        last_display = 0
        while self.running:
            time.sleep(1)  # Update every second
            
            current_time = time.time()
            if current_time - last_display > 3:  # Update every 3 seconds
                # Show only security statistics, not individual system events
                status_line = (
                    f"\r[🛡️] Security Events: {self.security_events} | "
                    f"System Activity: {self.system_events} (logged discretely)"
                )
                print(status_line, end="", flush=True)
                last_display = current_time
    
    def _get_process_info(self) -> Dict:
        """Get detailed process information."""
        try:
            pid = os.getppid()  # Get parent process ID for more accuracy
            process = psutil.Process(pid)
            return {
                "pid": pid,
                "name": process.name(),
                "username": process.username(),
                "cmdline": " ".join(process.cmdline())[:80]
            }
        except Exception:
            try:
                # Fallback to current process
                pid = os.getpid()
                process = psutil.Process(pid)
                return {
                    "pid": pid,
                    "name": process.name(),
                    "username": process.username(),
                    "cmdline": " ".join(process.cmdline())[:80]
                }
            except Exception:
                return {"pid": "unknown", "name": "unknown", "username": "unknown", "cmdline": "unknown"}
    
    def _classify_process(self, process_info: Dict) -> str:
        """Classify process as system, security, or user."""
        name = process_info.get('name', '').lower()
        username = process_info.get('username', '').lower()
        
        # Check security tools
        if any(sec_tool in name for sec_tool in self.security_processes):
            return 'security'
            
        # Check system processes
        if any(sys_proc in name for sys_proc in self.system_processes):
            return 'system'
            
        # Root processes - if they're security tools, they're security; otherwise system
        if username == 'root':
            if any(sec_tool in name for sec_tool in self.security_processes):
                return 'security'
            return 'system'
            
        # Regular user processes
        if username not in ['root', 'systemd-network', 'systemd-resolve', 'messagebus']:
            return 'user'
            
        return 'system'
    
    def _is_sensitive_file(self, file_path: str) -> bool:
        """Check if file is in sensitive locations."""
        for sensitive_path in self.sensitive_files:
            if sensitive_path.endswith('/'):
                # Directory check
                if file_path.startswith(sensitive_path):
                    return True
            else:
                # File check
                if file_path == sensitive_path:
                    return True
        return False
    
    def _should_ignore_file(self, file_path: str) -> bool:
        """Check if file should be completely ignored."""
        # System cache and temporary files
        system_ignore_patterns = [
            'ld.so.cache', 'locale.alias', '.Xauthority', '.ICEauthority',
            '.dbus', '.gvfs', '.recently-used', '.thumbnails',
            '.cache', '__pycache__', '.tmp', '.swp', '~',
            '.so', '.o', '.pyc', '.class', '.lock', '.pid',
            '/proc/', '/sys/', '/dev/', '.log.1', '.log.2', '.gz',
            'core.', 'swapfile', '.vdi', '.vmdk', '.iso'
        ]
        
        return any(pattern in file_path for pattern in system_ignore_patterns)
    
    def _is_security_relevant_file(self, file_path: str) -> bool:
        """Check if file is security-relevant (sensitive or user-accessible)."""
        # Sensitive files always trigger security alerts
        if self._is_sensitive_file(file_path):
            return True
            
        # User-accessible files in home or tmp directories
        user_paths = ['/home/', '/tmp/', '/var/tmp/']
        return any(path in file_path for path in user_paths)
    
    def _log_security_event(self, event_type: str, file_path: str, process_info: Dict):
        """Log and alert security events."""
        event = {
            'time': time.time(),
            'type': event_type,
            'file': file_path,
            'process': process_info.get('name', 'unknown'),
            'user': process_info.get('username', 'unknown'),
            'pid': process_info.get('pid', 'unknown')
        }
        self.security_queue.append(event)
        self.security_events += 1
        
        # Display security event with emphasis
        file_name = Path(file_path).name
        emoji_map = {'created': '🆕', 'modified': '✏️', 'deleted': '🗑️', 'moved': '➡️', 'accessed': '👁️'}
        emoji = emoji_map.get(event_type.lower(), '🚨')
        
        print(f"\n{emoji} [SECURITY] {process_info.get('username', 'unknown')} {event_type} '{file_name}' ⚠️")
    
    def _log_system_event(self, event_type: str, file_path: str, process_info: Dict):
        """Log system events discretely without alerts."""
        event = {
            'time': time.time(),
            'type': event_type,
            'file': file_path,
            'process': process_info.get('name', 'unknown'),
            'pid': process_info.get('pid', 'unknown')
        }
        self.system_queue.append(event)
        self.system_events += 1
        
        # Show discrete system activity (minimal output)
        if self.system_events % 10 == 0:  # Every 10th system event
            print(f"   [SYS] System activity count: {self.system_events}", end="\r", flush=True)
    
    def _send_security_alert(self, event_type: str, file_path: str, process_info: Dict):
        """Send security alerts for critical events."""
        timestamp = datetime.now()
        username = process_info.get('username', 'unknown')
        process_name = process_info.get('name', 'unknown')
        
        # Determine security level
        is_sensitive = self._is_sensitive_file(file_path)
        is_security_tool = self._classify_process(process_info) == 'security'
        
        security_level = "CRITICAL" if is_sensitive else "HIGH"
        emoji = "🚨🚨🚨" if is_sensitive else "⚠️⚠️⚠️"
        
        # System notification for immediate attention
        try:
            title = f"{emoji} {security_level} SECURITY ALERT"
            message = f"User: {username}\nAction: {event_type.upper()}\nFile: {Path(file_path).name}\nProcess: {process_name}"
            subprocess.run(['notify-send', '-u', 'critical', title, message], 
                          timeout=3, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        except:
            pass
        
        # Detailed email alert
        message = (
            f"🔐 PRIVAWARE {security_level} SECURITY ALERT 🔐\n"
            f"{'='*60}\n"
            f"🚨 EVENT TYPE: {event_type.upper()}\n"
            f"👤 USER: {username}\n"
            f"📅 DATE: {timestamp.strftime('%Y-%m-%d')}\n"
            f"⏰ TIME: {timestamp.strftime('%H:%M:%S')}\n"
            f"📁 FILE: {file_path}\n"
            f"⚙️  PROCESS: {process_name} (PID: {process_info.get('pid', 'unknown')})\n"
            f"🔗 FILE NAME: {Path(file_path).name}\n"
            f"🔐 SENSITIVE FILE: {'YES' if is_sensitive else 'NO'}\n"
            f"🔍 SECURITY TOOL: {'YES' if is_security_tool else 'NO'}\n"
            f"{'='*60}\n"
            f"🛡️  Monitored by PrivAware - Advanced Security Platform\n"
            f"⚠️  This indicates a potential security concern that requires attention."
        )
        
        subject = f"{emoji} PrivAware {security_level} Alert: {username} {event_type} {Path(file_path).name}"
        
        try:
            self.alert_sender.send_alert(subject=subject, message=message)
            print(f"📧 Security alert sent: {security_level}")
        except Exception as e:
            print(f"❌ Alert failed: {e}")
    
    def _handle_event(self, event_type: str, file_path: str):
        """Handle file events with security intelligence."""
        # Ignore certain files completely
        if self._should_ignore_file(file_path):
            return
            
        # Get process information
        process_info = self._get_process_info()
        process_type = self._classify_process(process_info)
        
        # Handle based on process type and file sensitivity
        if process_type == 'security':
            # Security tools always trigger alerts
            self._log_security_event(event_type, file_path, process_info)
            self._send_security_alert(event_type, file_path, process_info)
        elif process_type == 'system':
            # System processes - log discretely unless it's a sensitive file
            if self._is_sensitive_file(file_path):
                # Even system processes accessing sensitive files trigger alerts
                self._log_security_event(event_type, file_path, process_info)
                self._send_security_alert(event_type, file_path, process_info)
            else:
                # Regular system activity - log discretely
                self._log_system_event(event_type, file_path, process_info)
        elif process_type == 'user':
            # User processes - check if file is security-relevant
            if self._is_security_relevant_file(file_path):
                self._log_security_event(event_type, file_path, process_info)
                self._send_security_alert(event_type, file_path, process_info)
            else:
                # Non-security-relevant user activity - log discretely
                self._log_system_event(event_type, file_path, process_info)
        else:
            # Other processes - be conservative
            if self._is_sensitive_file(file_path):
                self._log_security_event(event_type, file_path, process_info)
                self._send_security_alert(event_type, file_path, process_info)
            else:
                self._log_system_event(event_type, file_path, process_info)
    
    def on_created(self, event):
        """Handle file creation events."""
        if not event.is_directory:
            self._handle_event('created', event.src_path)
    
    def on_deleted(self, event):
        """Handle file deletion events."""
        if not event.is_directory:
            self._handle_event('deleted', event.src_path)
    
    def on_modified(self, event):
        """Handle file modification events."""
        if not event.is_directory:
            try:
                if os.path.exists(event.src_path):
                    file_size = os.path.getsize(event.src_path)
                    if file_size > 0 or event.src_path.endswith(('.exe', '.sh', '.py', '.pl', '.txt', '.conf', '.cfg')):
                        self._handle_event('modified', event.src_path)
            except Exception:
                self._handle_event('modified', event.src_path)
    
    def on_moved(self, event):
        """Handle file move/rename events."""
        if not event.is_directory:
            self._handle_event('moved', event.dest_path)
    
    def on_opened(self, event):
        """Handle file access events."""
        if not event.is_directory:
            if self._is_security_relevant_file(event.src_path):
                self._handle_event('accessed', event.src_path)


class CoolFileWatcherManager:  # Keep original class name
    """Manager class for smart security-focused file watching."""
    
    def __init__(self, watch_paths=None, ignore_patterns=None):
        self.watch_paths = watch_paths or ["/home", "/tmp"]
        self.ignore_patterns = ignore_patterns or []
        self.observers = []
        self.event_handler = CoolFileEventMonitor(self.watch_paths, self.ignore_patterns)
        
    def start_monitoring(self):
        """Start security-focused monitoring."""
        print("🚀 Starting PrivAware Smart Security Monitor...")
        print("🛡️  Initializing intelligent security monitoring...")
        
        # Smart startup sequence
        startup_items = [
            "📁 Setting up security-focused file watchers...",
            "🤖 Configuring security process filters...",
            "🚨 Setting up security alert system...",
            "📧 Initializing email alerts...",
            "🔔 Initializing system notifications...",
            "🔍 Preparing sensitive file monitoring...",
            "📊 Starting discrete system logging..."
        ]
        
        for item in startup_items:
            print(f"   {item}")
            time.sleep(0.15)
        
        print("\n✅ PrivAware Smart Security Monitor Active!")
        print("🚨 Security events: ALERT with notifications")
        print("🔧 System events: Logged discretely (no popups)")
        print("🔐 Sensitive file access: CRITICAL alerts")
        print("🔍 Security tool usage: IMMEDIATE alerts")
        print("💡 Press Ctrl+C to stop monitoring\n")
        
        for path in self.watch_paths:
            path_obj = Path(path)
            if path_obj.exists():
                observer = Observer()
                observer.schedule(self.event_handler, path=str(path_obj), recursive=True)
                observer.start()
                self.observers.append(observer)
                print(f"🎯 Monitoring: {path}")
            else:
                print(f"⚠️  Warning: Path does not exist: {path}")
        
        print(f"\n📈 Monitoring {len(self.observers)} locations")
        print("🔄 Smart security monitoring started...\n")
        print("🔒 Only security-relevant events will trigger alerts!")
        
    def stop_monitoring(self):
        """Stop monitoring with security summary."""
        print("\n\n🛑 Stopping PrivAware Smart Security Monitor...")
        self.event_handler.running = False
        
        for observer in self.observers:
            observer.stop()
            
        for observer in self.observers:
            observer.join()
            
        # Show security summary
        security_count = self.event_handler.security_events
        system_count = self.event_handler.system_events
        
        print(f"\n📊 SECURITY MONITORING SUMMARY:")
        print(f"   🚨 Security Events: {security_count}")
        print(f"   🔧 System Events (logged): {system_count}")
        print(f"   🛡️  Security Focus: {security_count > 0}")
        
        print("👋 PrivAware Smart Security Monitor stopped. Stay secure!")


def main():
    """Main entry point with security-focused demo mode."""
    print("🎯 PrivAware Smart Security Monitor - Demo Mode")
    print("=" * 60)
    print("🔒 FOCUS: Security-relevant events only")
    print("🔔 ALERTS: Security events only (no system noise)")
    print("📝 LOGS: System activity (discrete, no popups)")
    print("=" * 60)
    
    # Default security-focused monitoring
    watch_paths = [
        "/home",  # User home directories (security focus)
        "/tmp"    # Temporary files (potential attack vectors)
    ]
    
    # Create and start the smart security watcher
    watcher_manager = CoolFileWatcherManager(watch_paths, [])
    
    try:
        watcher_manager.start_monitoring()
        print("\n🔥 SMART SECURITY MONITORING ACTIVE!")
        print("💡 Only security events trigger alerts")
        print("💡 System activity logged discretely")
        print("💡 Try creating/modifying sensitive files to test...")
        
        # Keep running
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\n\n⚠️  Received interrupt signal")
        watcher_manager.stop_monitoring()


if __name__ == "__main__":
    main()
