"""
System Monitor: Tracks system health and anomalies with real-time alerts.
"""
import os
import json
import shutil
import psutil
import time
from datetime import datetime
import threading
from queue import Queue

SETTINGS_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'config', 'settings.json'))

def load_settings():
    with open(SETTINGS_PATH, 'r') as f:
        return json.load(f)

class Alert:
    def __init__(self, metric, value, threshold, message):
        self.timestamp = datetime.now()
        self.metric = metric
        self.value = value
        self.threshold = threshold
        self.message = message
    
    def __str__(self):
        return f"[{self.timestamp.strftime('%H:%M:%S')}] {self.metric}: {self.value} (threshold: {self.threshold}) - {self.message}"

class SystemMonitor:
    def __init__(self, alert_callback=None):
        self.settings = load_settings()
        monitor = self.settings.get('monitor', {})
        self.cpu_threshold = monitor.get('cpu_threshold', 90)
        self.memory_threshold = monitor.get('memory_threshold', 90)
        self.disk_threshold = monitor.get('disk_threshold', 90)
        self.temperature_threshold = monitor.get('temperature_threshold', 80)
        self.load_threshold = monitor.get('load_threshold', 2.0)
        self.alert_callback = alert_callback
        self.alert_history = []
        self.last_values = {}

    def check_cpu(self):
        usage = psutil.cpu_percent(interval=1)
        alert_triggered = usage > self.cpu_threshold
        
        if alert_triggered:
            alert = Alert(
                'CPU', usage, self.cpu_threshold,
                f'High CPU usage detected: {usage:.1f}%'
            )
            self._handle_alert(alert)
        
        return {
            'usage': usage,
            'alert': alert_triggered,
            'cores': psutil.cpu_count(),
            'logical_cores': psutil.cpu_count(logical=True)
        }

    def check_memory(self):
        mem = psutil.virtual_memory()
        alert_triggered = mem.percent > self.memory_threshold
        
        if alert_triggered:
            alert = Alert(
                'Memory', mem.percent, self.memory_threshold,
                f'High memory usage detected: {mem.percent:.1f}%'
            )
            self._handle_alert(alert)
        
        return {
            'usage': mem.percent,
            'alert': alert_triggered,
            'total': mem.total,
            'available': mem.available,
            'used': mem.used
        }

    def check_disk(self):
        usage = shutil.disk_usage('/')
        percent = usage.used / usage.total * 100
        alert_triggered = percent > self.disk_threshold
        
        if alert_triggered:
            alert = Alert(
                'Disk', percent, self.disk_threshold,
                f'Low disk space: {percent:.1f}% used'
            )
            self._handle_alert(alert)
        
        return {
            'usage': percent,
            'alert': alert_triggered,
            'total': usage.total,
            'used': usage.used,
            'free': usage.free
        }

    def check_load_average(self):
        try:
            load_avg = os.getloadavg()
            cores = psutil.cpu_count()
            normalized_load = load_avg[0] / cores if cores else load_avg[0]
            alert_triggered = normalized_load > self.load_threshold
            
            if alert_triggered:
                alert = Alert(
                    'Load', load_avg[0], self.load_threshold,
                    f'High system load: {load_avg[0]:.2f}'
                )
                self._handle_alert(alert)
            
            return {
                'usage': load_avg[0],
                'alert': alert_triggered,
                'load_5min': load_avg[1],
                'load_15min': load_avg[2],
                'cores': cores
            }
        except:
            return {
                'usage': 0,
                'alert': False,
                'load_5min': 0,
                'load_15min': 0,
                'cores': 0
            }

    def check_temperature(self):
        try:
            temps = psutil.sensors_temperatures()
            if temps and 'coretemp' in temps:
                cpu_temp = temps['coretemp'][0].current
                alert_triggered = cpu_temp > self.temperature_threshold
                
                if alert_triggered:
                    alert = Alert(
                        'Temperature', cpu_temp, self.temperature_threshold,
                        f'High CPU temperature: {cpu_temp:.1f}°C'
                    )
                    self._handle_alert(alert)
                
                return {
                    'usage': cpu_temp,
                    'alert': alert_triggered,
                    'high': temps['coretemp'][0].high,
                    'critical': temps['coretemp'][0].critical
                }
            else:
                return {
                    'usage': 0,
                    'alert': False,
                    'message': 'Temperature monitoring not available'
                }
        except:
            return {
                'usage': 0,
                'alert': False,
                'message': 'Temperature monitoring not available'
            }

    def _handle_alert(self, alert):
        """Handle alert generation and notification"""
        self.alert_history.append(alert)
        if len(self.alert_history) > 100:  # Keep last 100 alerts
            self.alert_history.pop(0)
        
        if self.alert_callback:
            self.alert_callback(alert)
        else:
            print(f"🚨 ALERT: {alert}")

    def run_all(self):
        return {
            'cpu': self.check_cpu(),
            'memory': self.check_memory(),
            'disk': self.check_disk(),
            'load': self.check_load_average(),
            'temperature': self.check_temperature()
        }

    def start_realtime_monitoring(self, interval=5):
        """Start real-time monitoring in a separate thread"""
        def monitor_loop():
            print(f"🚀 Starting real-time monitoring (interval: {interval}s)")
            print("Press Ctrl+C to stop")
            
            while True:
                try:
                    results = self.run_all()
                    timestamp = datetime.now().strftime('%H:%M:%S')
                    
                    # Check for alerts and print status
                    alerts = [k for k, v in results.items() if v.get('alert', False)]
                    if alerts:
                        print(f"[{timestamp}] ⚠  ALERTS: {', '.join(alerts)}")
                    else:
                        print(f"[{timestamp}] ✓ All systems normal")
                    
                    time.sleep(interval)
                except KeyboardInterrupt:
                    print("\n🛑 Stopping real-time monitoring...")
                    break
                except Exception as e:
                    print(f"[{timestamp}] ❌ Error: {e}")
                    time.sleep(interval)
        
        monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
        monitor_thread.start()
        return monitor_thread

    def get_alert_history(self, limit=10):
        """Get recent alert history"""
        return self.alert_history[-limit:] if self.alert_history else []

    def get_system_status(self):
        """Get current system status summary"""
        results = self.run_all()
        alerts = [k for k, v in results.items() if v.get('alert', False)]
        return {
            'status': 'ALERT' if alerts else 'OK',
            'alerts': alerts,
            'total_metrics': len(results),
            'alerting_metrics': len(alerts)
        }

# Email/SMS Alert Integration (example)
def send_email_alert(alert):
    """Example email alert function - implement based on your needs"""
    try:
        # You can integrate with smtplib, sendgrid, etc.
        print(f"📧 Email Alert Sent: {alert}")
        # Implementation would go here
    except Exception as e:
        print(f"❌ Failed to send email alert: {e}")

def send_slack_alert(alert):
    """Example Slack alert function"""
    try:
        # Integrate with Slack webhook
        print(f"💬 Slack Alert Sent: {alert}")
        # Implementation would go here
    except Exception as e:
        print(f"❌ Failed to send Slack alert: {e}")

if __name__ == "__main__":
    # Example usage with email alerts
    def alert_handler(alert):
        print(f"🚨 NEW ALERT: {alert}")
        # Uncomment to enable email alerts:
        # send_email_alert(alert)
    
    monitor = SystemMonitor(alert_callback=alert_handler)
    
    # Run one-time check
    print("📊 System Health Check:")
    results = monitor.run_all()
    for k, v in results.items():
        usage = v.get('usage', 'N/A')
        alert = v.get('alert', False)
        status = "⚠ ALERT" if alert else "✓ OK"
        print(f"  {k.upper()}: {usage:.1f}% {status}")
    
    print("\n" + "="*50)
    print("Starting real-time monitoring...")
    print("="*50)
    
    # Start real-time monitoring
    try:
        monitor.start_realtime_monitoring(interval=3)
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n👋 Monitoring stopped.")
