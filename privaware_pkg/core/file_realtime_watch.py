# core/file_realtime_watch.py
"""
File Real-Time Watcher: Intelligent file system monitoring with cool visualization.
Tracks user CRUD operations while silently monitoring system activity.
"""

import os
import time
import pwd
import psutil
from pathlib import Path
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from collections import defaultdict, deque
from typing import Dict
import threading

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

class CoolFileEventMonitor(FileSystemEventHandler):
    """Enhanced file event handler with cool monitoring and intelligent alerts."""
    
    def __init__(self, watch_paths=None, ignore_patterns=None):
        super().__init__()
        self.alert_sender = AlertSender()
        self.watch_paths = watch_paths or ["/home", "/tmp"]
        self.ignore_patterns = ignore_patterns or []
        self.running = True
        
        # Cool statistics tracking
        self.stats = {
            'created': 0,
            'modified': 0,
            'deleted': 0,
            'accessed': 0,
            'moved': 0
        }
        
        # System activity tracking (no alerts)
        self.system_activity = deque(maxlen=50)  # Last 50 system events
        self.user_activity = deque(maxlen=20)    # Last 20 user events
        
        # Process classification
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
        
        # User tools that we care about
        self.user_processes = {
            'nano', 'vim', 'vi', 'gedit', 'code', 'subl', 'atom',
            'touch', 'mkdir', 'rm', 'cp', 'mv', 'python', 'python3',
            'bash', 'sh', 'zsh', 'konsole', 'gnome-terminal', 'xterm',
            'firefox', 'chrome', 'chromium', 'thunderbird', 'gedit',
            'libreoffice', 'mousepad', 'pluma', 'leafpad'
        }
        
        # Start the cool display thread
        self.display_thread = threading.Thread(target=self._cool_display, daemon=True)
        self.display_thread.start()
        
    def _cool_display(self):
        """Cool real-time display of system vs user activity."""
        import sys
        last_display = 0
        while self.running:
            time.sleep(2)  # Update every 2 seconds
            
            # Only display if we have recent activity
            current_time = time.time()
            if current_time - last_display > 5:  # Display every 5 seconds max
                system_recent = [e for e in self.system_activity if current_time - e.get('time', 0) < 10]
                user_recent = [e for e in self.user_activity if current_time - e.get('time', 0) < 10]
                
                if system_recent or user_recent:
                    system_count = len(system_recent)
                    user_count = len(user_recent)
                    status_line = (
                        f"\r[🛡️] C:{self.stats['created']} M:{self.stats['modified']} D:{self.stats['deleted']} | "
                        f"🤖:{system_count} 👤:{user_count}"
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
        """Classify process as system, user, or neutral."""
        name = process_info.get('name', '').lower()
        username = process_info.get('username', '').lower()
        
        # Check system processes
        if any(sys_proc in name for sys_proc in self.system_processes):
            return 'system'
            
        # Check user processes
        if any(user_proc in name for user_proc in self.user_processes):
            return 'user'
            
        # Root processes are usually system unless they're user tools
        if username == 'root':
            if any(user_tool in name for user_tool in ['nano', 'vim', 'python', 'bash', 'touch', 'mkdir']):
                return 'user'
            return 'system'
            
        # User processes (non-root users)
        if username not in ['root', 'systemd-network', 'systemd-resolve', 'messagebus']:
            return 'user'
            
        return 'neutral'
    
    def _should_ignore_file(self, file_path: str) -> bool:
        """Check if file should be completely ignored."""
        # System cache and temporary files
        system_ignore_patterns = [
            'ld.so.cache', 'locale.alias', '.Xauthority', '.ICEauthority',
            '.dbus', '.gvfs', '.recently-used', '.thumbnails',
            '.cache', '__pycache__', '.tmp', '.swp', '~',
            '.so', '.o', '.pyc', '.class', '.lock', '.pid',
            '/proc/', '/sys/', '/dev/'
        ]
        
        return any(pattern in file_path for pattern in system_ignore_patterns)
    
    def _is_user_relevant_file(self, file_path: str) -> bool:
        """Check if file is relevant to user monitoring."""
        # Focus on user directories and common user file locations
        user_paths = ['/home/', '/tmp/', '/var/tmp/']
        return any(path in file_path for path in user_paths)
    
    def _log_system_activity(self, event_type: str, file_path: str, process_info: Dict):
        """Log system activity without alerting."""
        activity = {
            'time': time.time(),
            'type': event_type,
            'file': file_path,
            'process': process_info.get('name', 'unknown'),
            'pid': process_info.get('pid', 'unknown')
        }
        self.system_activity.append(activity)
    
    def _log_user_activity(self, event_type: str, file_path: str, process_info: Dict):
        """Log and alert user activity."""
        activity = {
            'time': time.time(),
            'type': event_type,
            'file': file_path,
            'process': process_info.get('name', 'unknown'),
            'user': process_info.get('username', 'unknown')
        }
        self.user_activity.append(activity)
        
        # Cool user activity display
        file_name = Path(file_path).name
        emoji_map = {'created': '🆕', 'modified': '✏️', 'deleted': '🗑️', 'moved': '➡️', 'accessed': '👁️'}
        emoji = emoji_map.get(event_type.lower(), '📁')
        
        print(f"\n[{emoji} USER] {process_info.get('username', 'unknown')} {event_type} '{file_name}'")
    
    def _send_user_alert(self, event_type: str, file_path: str, process_info: Dict):
        """Send alert for user-initiated file operations."""
        timestamp = datetime.now()
        username = process_info.get('username', 'unknown')
        process_name = process_info.get('name', 'unknown')
        
        # Cool formatted message
        message = (
            f"🔐 PrivAware Security Alert 🔐\n"
            f"{'='*40}\n"
            f"🚨 EVENT: {event_type.upper()} 🚨\n"
            f"👤 User: {username}\n"
            f"📅 Date: {timestamp.strftime('%Y-%m-%d')}\n"
            f"⏰ Time: {timestamp.strftime('%H:%M:%S')}\n"
            f"📁 File: {file_path}\n"
            f"⚙️  Process: {process_name} (PID: {process_info.get('pid', 'unknown')})\n"
            f"{'='*40}\n"
            f"🛡️  Monitored by PrivAware - Your Linux Security Companion"
        )
        
        subject = f"PrivAware Alert: {username} {event_type} {Path(file_path).name}"
        
        try:
            self.alert_sender.send_alert(subject=subject, message=message)
            print(f"📧 Alert sent for user {event_type} operation")
        except Exception as e:
            print(f"❌ Alert failed: {e}")
    
    def _handle_event(self, event_type: str, file_path: str):
        """Handle file events intelligently."""
        # Update statistics
        self.stats[event_type.lower()] = self.stats.get(event_type.lower(), 0) + 1
        
        # Ignore certain files completely
        if self._should_ignore_file(file_path):
            return
            
        # Get process information
        process_info = self._get_process_info()
        process_type = self._classify_process(process_info)
        
        # Handle based on process type
        if process_type == 'system':
            # Log system activity silently
            self._log_system_activity(event_type, file_path, process_info)
        elif process_type == 'user':
            # Log and alert user activity
            self._log_user_activity(event_type, file_path, process_info)
            # Only send alerts for CRUD operations in user-relevant locations
            if self._is_user_relevant_file(file_path) and event_type in ['created', 'modified', 'deleted', 'moved']:
                self._send_user_alert(event_type, file_path, process_info)
        else:
            # Neutral processes - log if in user-relevant locations
            if self._is_user_relevant_file(file_path):
                self._log_user_activity(event_type, file_path, process_info)
    
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
            # Only alert on significant modifications
            try:
                if os.path.exists(event.src_path):
                    file_size = os.path.getsize(event.src_path)
                    # Only process files that are not empty or are executables
                    if file_size > 0 or event.src_path.endswith(('.exe', '.sh', '.py', '.pl', '.txt')):
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
            # Be very selective about access events
            if self._is_user_relevant_file(event.src_path):
                self._handle_event('accessed', event.src_path)


class CoolFileWatcherManager:
    """Manager class for cool file watching with awesome features."""
    
    def __init__(self, watch_paths=None, ignore_patterns=None):
        self.watch_paths = watch_paths or ["/home", "/tmp"]
        self.ignore_patterns = ignore_patterns or []
        self.observers = []
        self.event_handler = CoolFileEventMonitor(self.watch_paths, self.ignore_patterns)
        
    def start_monitoring(self):
        """Start monitoring with cool startup sequence."""
        print("🚀 Starting PrivAware File Monitor...")
        print("🛡️  Initializing security monitoring...")
        
        # Cool startup animation
        startup_items = [
            "📁 Setting up file watchers...",
            "🤖 Configuring system filters...",
            "📧 Initializing alert system...",
            "📊 Preparing real-time analytics..."
        ]
        
        for item in startup_items:
            print(f"   {item}")
            time.sleep(0.2)
        
        print("\n✅ PrivAware File Monitor Active!")
        print("💡 Tip: User CRUD operations will trigger alerts")
        print("💡 Tip: System activity is monitored silently")
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
        print("🔄 Real-time monitoring started...\n")
        
    def stop_monitoring(self):
        """Stop monitoring with cool shutdown."""
        print("\n🛑 Stopping PrivAware File Monitor...")
        self.event_handler.running = False
        
        for observer in self.observers:
            observer.stop()
            
        for observer in self.observers:
            observer.join()
            
        # Show final statistics
        stats = self.event_handler.stats
        print(f"\n📊 Final Statistics:")
        print(f"   🆕 Created: {stats['created']}")
        print(f"   ✏️  Modified: {stats['modified']}")
        print(f"   🗑️  Deleted: {stats['deleted']}")
        print(f"   ➡️  Moved: {stats['moved']}")
        print(f"   👁️  Accessed: {stats['accessed']}")
        
        print("👋 PrivAware File Monitor stopped. Stay secure!")


def main():
    """Main entry point with cool demo mode."""
    print("🎯 PrivAware File Monitor - Demo Mode")
    print("=" * 50)
    
    # Default user-focused monitoring
    watch_paths = [
        "/home",  # User home directories
        "/tmp"    # Temporary files
    ]
    
    ignore_patterns = []  # Let the intelligent system handle filtering
    
    # Create and start the cool file watcher
    watcher_manager = CoolFileWatcherManager(watch_paths, ignore_patterns)
    
    try:
        watcher_manager.start_monitoring()
        print("🔥 Monitoring active! Try creating/modifying files in your home directory...")
        
        # Keep running
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\n\n⚠️  Received interrupt signal")
        watcher_manager.stop_monitoring()


if __name__ == "__main__":
    main()
