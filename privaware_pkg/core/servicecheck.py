# core/servicecheck.py - Enhanced Advanced Service Monitor
"""
Advanced Service Monitor: Intelligent service monitoring with cool visualization.
Monitors critical services, provides health status, and sends alerts for failures.
"""
import os
import json
import subprocess
import time
from datetime import datetime
from typing import Dict, List, Tuple
import threading
import psutil
from collections import defaultdict

try:
    from .alerts import AlertSender
except ImportError:
    # Fallback for direct execution or import issues
    try:
        from alerts import AlertSender
    except ImportError:
        # Create a mock alert sender if not available
        class AlertSender:
            def send_alert(self, subject, message):
                print(f"[MOCK ALERT] Subject: {subject}")
                print(f"[MOCK ALERT] Message: {message}")

class AdvancedServiceMonitor:
    """Advanced service monitoring with intelligent health checks and alerts."""
    
    def __init__(self):
        self.alert_sender = AlertSender()
        self.services = [
            'sshd', 'apache2', 'nginx', 'mysql', 'postgresql', 
            'docker', 'firewalld', 'ufw', 'cron', 'systemd',
            'NetworkManager', 'bluetooth', 'cups', 'avahi-daemon'
        ]
        self.service_status = {}
        self.service_history = defaultdict(list)
        self.monitoring = False
        self.monitor_thread = None
        
        # Service categories for better organization
        self.service_categories = {
            'security': ['sshd', 'firewalld', 'ufw', 'fail2ban'],
            'web': ['apache2', 'nginx', 'httpd'],
            'database': ['mysql', 'postgresql', 'mariadb'],
            'system': ['systemd', 'cron', 'rsyslog', 'syslog-ng'],
            'network': ['NetworkManager', 'networking', 'dnsmasq'],
            'docker': ['docker', 'containerd'],
            'printing': ['cups'],
            'discovery': ['avahi-daemon', 'bluetooth']
        }
        
        # Critical services that require immediate alerts
        self.critical_services = ['sshd', 'firewalld', 'ufw', 'systemd', 'cron']
        
    def _run_command(self, cmd: List[str], timeout: int = 10) -> Tuple[bool, str, str]:
        """Run command with timeout and error handling."""
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return result.returncode == 0, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return False, "", "Command timed out"
        except Exception as e:
            return False, "", str(e)
    
    def check_service_status(self, service: str) -> Dict:
        """Check status of a single service with detailed information."""
        # Try systemctl first (modern systems)
        is_active, stdout, stderr = self._run_command(['systemctl', 'is-active', service])
        
        if is_active and stdout.strip() in ['active', 'activating']:
            # Get more detailed info
            _, status_out, _ = self._run_command(['systemctl', 'status', service])
            
            # Extract process info
            process_info = self._get_service_processes(service)
            
            return {
                'status': 'RUNNING',
                'method': 'systemctl',
                'message': f'Service {service} is active',
                'processes': process_info,
                'uptime': self._get_service_uptime(service),
                'memory_usage': self._get_service_memory_usage(service),
                'cpu_usage': self._get_service_cpu_usage(service)
            }
        
        # Try service command (legacy systems)
        is_running, stdout, stderr = self._run_command(['service', service, 'status'])
        
        if is_running and 'running' in stdout.lower():
            return {
                'status': 'RUNNING',
                'method': 'service',
                'message': f'Service {service} is running',
                'processes': [],
                'uptime': 0,
                'memory_usage': 0,
                'cpu_usage': 0
            }
        
        # Service is not running
        return {
            'status': 'STOPPED',
            'method': 'systemctl' if is_active else 'service',
            'message': f'Service {service} is not running',
            'processes': [],
            'uptime': 0,
            'memory_usage': 0,
            'cpu_usage': 0
        }
    
    def _get_service_processes(self, service: str) -> List[Dict]:
        """Get process information for the service."""
        processes = []
        try:
            for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline']):
                if service.lower() in proc.info['name'].lower() or service.lower() in ' '.join(proc.info['cmdline']).lower():
                    processes.append({
                        'pid': proc.info['pid'],
                        'name': proc.info['name'],
                        'username': proc.info['username'],
                        'cmdline': ' '.join(proc.info['cmdline'])[:100]  # Truncate long commands
                    })
        except Exception:
            pass
        return processes
    
    def _get_service_uptime(self, service: str) -> float:
        """Get service uptime in seconds."""
        try:
            # Get service start time from systemctl
            is_ok, stdout, _ = self._run_command(['systemctl', 'show', service, '--property=ActiveEnterTimestamp'])
            if is_ok and 'ActiveEnterTimestamp=' in stdout:
                timestamp_str = stdout.split('=', 1)[1].strip()
                if timestamp_str and timestamp_str != 'inactive':
                    try:
                        # Parse the timestamp (format: Wed 2023-10-15 14:30:45 UTC)
                        timestamp = datetime.strptime(' '.join(timestamp_str.split()[-3:]), '%Y-%m-%d %H:%M:%S')
                        uptime = (datetime.now() - timestamp).total_seconds()
                        return uptime
                    except:
                        pass
        except:
            pass
        return 0
    
    def _get_service_memory_usage(self, service: str) -> int:
        """Get memory usage for service processes."""
        total_memory = 0
        try:
            for proc in psutil.process_iter(['pid', 'memory_info']):
                try:
                    if service.lower() in proc.name().lower():
                        total_memory += proc.memory_info().rss
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except:
            pass
        return total_memory
    
    def _get_service_cpu_usage(self, service: str) -> float:
        """Get CPU usage for service processes."""
        total_cpu = 0
        try:
            for proc in psutil.process_iter(['pid', 'cpu_percent']):
                try:
                    if service.lower() in proc.name().lower():
                        total_cpu += proc.cpu_percent()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except:
            pass
        return total_cpu
    
    def check_all_services(self) -> Dict[str, Dict]:
        """Check status of all services."""
        results = {}
        for service in self.services:
            results[service] = self.check_service_status(service)
            
            # Store in history
            self.service_history[service].append({
                'timestamp': datetime.now().isoformat(),
                'status': results[service]['status'],
                'message': results[service]['message']
            })
            
            # Keep only last 10 history entries
            if len(self.service_history[service]) > 10:
                self.service_history[service] = self.service_history[service][-10:]
        
        self.service_status = results
        return results
    
    def get_service_category(self, service: str) -> str:
        """Get category for a service."""
        for category, services in self.service_categories.items():
            if service in services:
                return category
        return 'other'
    
    def categorize_services(self, results: Dict) -> Dict:
        """Categorize services by type."""
        categorized = {}
        for category, services in self.service_categories.items():
            categorized[category] = {}
            for service in services:
                if service in results:
                    categorized[category][service] = results[service]
        
        # Add 'other' category for uncategorized services
        categorized['other'] = {}
        for service, status in results.items():
            if service not in [s for sublist in self.service_categories.values() for s in sublist]:
                categorized['other'][service] = status
        
        return categorized
    
    def get_health_score(self, results: Dict) -> Dict:
        """Calculate health score for services."""
        total = len(results)
        running = sum(1 for status in results.values() if status['status'] == 'RUNNING')
        critical_running = sum(1 for service, status in results.items() 
                              if service in self.critical_services and status['status'] == 'RUNNING')
        
        score = (running / total * 100) if total > 0 else 0
        critical_score = (critical_running / len(self.critical_services) * 100) if self.critical_services else 0
        
        return {
            'overall_score': round(score, 1),
            'critical_score': round(critical_score, 1),
            'running_services': running,
            'total_services': total,
            'status': 'CRITICAL' if critical_score < 50 else 'WARNING' if critical_score < 80 else 'HEALTHY'
        }
    
    def send_service_alert(self, service: str, status: str, message: str):
        """Send alert for service status change."""
        if service in self.critical_services or status == 'STOPPED':
            timestamp = datetime.now()
            
            # System notification
            try:
                import subprocess
                subprocess.run(['notify-send', f'🚨 Service Alert: {service}', 
                               f'Status: {status}\n{message}'], 
                              timeout=3, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
            except:
                pass
            
            # Email alert
            subject = f"🚨 PrivAware Service Alert: {service} is {status}"
            message_body = f"""
🔐 PRIVAWARE SERVICE MONITORING ALERT 🔐
{'='*50}
🚨 SERVICE: {service}
📊 STATUS: {status}
📅 TIME: {timestamp.strftime('%Y-%m-%d %H:%M:%S')}
📝 MESSAGE: {message}
{'='*50}
🛡️  Monitored by PrivAware - Advanced Service Monitoring
⚠️  This indicates a potential system issue that requires attention.
            """
            
            try:
                self.alert_sender.send_alert(subject, message_body)
                print(f"📧 Service alert sent for {service}")
            except Exception as e:
                print(f"❌ Alert failed for {service}: {e}")
    
    def start_monitoring(self, interval: int = 60):
        """Start continuous service monitoring."""
        self.monitoring = True
        
        def monitor_loop():
            while self.monitoring:
                results = self.check_all_services()
                
                # Check for status changes and send alerts
                for service, status_info in results.items():
                    current_status = status_info['status']
                    
                    # Check if status changed from previous check
                    if service in self.service_status:
                        previous_status = self.service_status[service]['status']
                        if previous_status != current_status:
                            self.send_service_alert(service, current_status, status_info['message'])
                    else:
                        # New service being monitored
                        if current_status == 'STOPPED' and service in self.critical_services:
                            self.send_service_alert(service, current_status, status_info['message'])
                
                time.sleep(interval)
        
        self.monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
        self.monitor_thread.start()
        print(f"🔄 Service monitoring started (interval: {interval}s)")
    
    def stop_monitoring(self):
        """Stop continuous service monitoring."""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2)
        print("🛑 Service monitoring stopped")
    
    def get_service_trends(self, service: str, hours: int = 24) -> List[Dict]:
        """Get service status trends for the specified time period."""
        trends = []
        cutoff_time = datetime.now().timestamp() - (hours * 3600)
        
        for entry in self.service_history[service]:
            entry_time = datetime.fromisoformat(entry['timestamp'].replace('Z', '+00:00')).timestamp()
            if entry_time >= cutoff_time:
                trends.append(entry)
        
        return trends
    
    def get_system_health_report(self) -> str:
        """Generate a comprehensive system health report."""
        results = self.check_all_services()
        health = self.get_health_score(results)
        categorized = self.categorize_services(results)
        
        report = []
        report.append("🛡️ PRIVAWARE SYSTEM HEALTH REPORT 🛡️")
        report.append("=" * 60)
        report.append(f"📅 Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"📊 Overall Health: {health['overall_score']}%")
        report.append(f"🔒 Critical Services: {health['critical_score']}%")
        report.append(f"📈 Running: {health['running_services']}/{health['total_services']}")
        report.append("")
        
        # Show categorized services
        for category, services in categorized.items():
            if services:  # Only show categories that have services
                report.append(f"📁 {category.upper()} SERVICES:")
                for service, status in services.items():
                    status_icon = "🟢" if status['status'] == 'RUNNING' else "🔴"
                    uptime = f" ({status['uptime']:.0f}s)" if status['uptime'] > 0 else ""
                    report.append(f"  {status_icon} {service}: {status['status']}{uptime}")
                report.append("")
        
        # Show critical services summary
        critical_status = []
        for service in self.critical_services:
            if service in results:
                status = results[service]['status']
                critical_status.append(f"{service}: {status}")
        
        if critical_status:
            report.append("🚨 CRITICAL SERVICES SUMMARY:")
            for status_str in critical_status:
                report.append(f"  • {status_str}")
            report.append("")
        
        return "\n".join(report)

class ServiceChecker:
    """Compatibility class for backward compatibility."""
    
    def __init__(self):
        self.monitor = AdvancedServiceMonitor()
    
    def check_services(self, services: List[str] = None) -> Dict:
        """Check services (for backward compatibility)."""
        if services:
            self.monitor.services = services
        results = self.monitor.check_all_services()
        
        # Convert to old format for compatibility
        old_format = {}
        for service, status_info in results.items():
            old_format[service] = {
                'status': status_info['status'],
                'message': status_info['message']
            }
        
        return old_format

if __name__ == "__main__":
    checker = AdvancedServiceMonitor()
    results = checker.check_all_services()
    
    print("🎯 Advanced Service Monitor - Current Status")
    print("=" * 50)
    
    for service, status in results.items():
        icon = "🟢" if status['status'] == 'RUNNING' else "🔴"
        print(f"{icon} {service}: {status['status']} - {status['message']}")
    
    health = checker.get_health_score(results)
    print(f"\n📊 Health Score: {health['overall_score']}%")
    print(f"🔒 Critical Score: {health['critical_score']}%")
