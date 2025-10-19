# privaware_pkg/core/enhanced_dashboard.py
"""
Enhanced Real-Time System Monitor Dashboard with ASCII Charts
"""
import psutil
import time
import shutil
from datetime import datetime
from collections import deque

class EnhancedSystemDashboard:
    def __init__(self):
        self.history_size = 60
        self.cpu_history = deque(maxlen=self.history_size)
        self.mem_history = deque(maxlen=self.history_size)
        self.disk_history = deque(maxlen=self.history_size)
        self.load_history = deque(maxlen=self.history_size)
        self.temp_history = deque(maxlen=self.history_size)
        self.prev_net_io = None
        self.prev_time = None
        self.net_upload_history = deque(maxlen=self.history_size)
        self.net_download_history = deque(maxlen=self.history_size)
        
        # Thresholds for status indicators
        self.cpu_threshold = 80
        self.mem_threshold = 85
        self.disk_threshold = 90
        self.load_threshold = 1.5
        self.temp_threshold = 75
        
    def _bytes_to_human(self, bytes_val):
        """Convert bytes to human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_val < 1024.0:
                return f"{bytes_val:.1f} {unit}"
            bytes_val /= 1024.0
        return f"{bytes_val:.1f} PB"
    
    def _rate_to_human(self, bytes_per_sec):
        """Convert bytes per second to human readable format"""
        for unit in ['B/s', 'KB/s', 'MB/s', 'GB/s']:
            if bytes_per_sec < 1024.0:
                return f"{bytes_per_sec:.1f} {unit}"
            bytes_per_sec /= 1024.0
        return f"{bytes_per_sec:.1f} TB/s"
    
    def _create_ascii_bar(self, value, max_value=100, width=20):
        """Create ASCII bar chart"""
        filled = int((value / max_value) * width)
        bar = "█" * filled + "░" * (width - filled)
        return f"[{bar}] {value:.1f}%"
    
    def _create_sparkline(self, data, width=20):
        """Create ASCII sparkline chart"""
        if len(data) < 2:
            return " " * width
            
        min_val = min(data) if min(data) != max(data) else 0
        max_val = max(data)
        range_val = max_val - min_val if max_val != min_val else 1
        
        spark_chars = "▁▂▃▄▅▆▇█"
        normalized = [(val - min_val) / range_val if range_val > 0 else 0 for val in data]
        
        if len(normalized) > width:
            step = len(normalized) / width
            sampled = [normalized[int(i * step)] for i in range(width)]
        else:
            sampled = normalized + [0] * (width - len(normalized))
            
        sparkline = "".join(spark_chars[int(val * (len(spark_chars) - 1))] for val in sampled)
        return sparkline
    
    def _get_status_emoji(self, value, warning_threshold, critical_threshold, reverse=False):
        """Get emoji based on value thresholds"""
        if reverse:  # For disk usage, higher is worse
            if value >= critical_threshold:
                return "🔴"  # Critical
            elif value >= warning_threshold:
                return "🟡"  # Warning
        else:  # For CPU/Memory, higher is worse
            if value >= critical_threshold:
                return "🔴"  # Critical
            elif value >= warning_threshold:
                return "🟡"  # Warning
        return "🟢"  # OK
    
    def _clear_screen(self):
        """Clear terminal screen"""
        print("\033[2J\033[H", end="")
    
    def get_system_metrics(self):
        """Get comprehensive system metrics"""
        metrics = {}
        
        # CPU
        metrics['cpu'] = psutil.cpu_percent(interval=0.1)
        metrics['cpu_cores'] = psutil.cpu_count()
        metrics['cpu_logical_cores'] = psutil.cpu_count(logical=True)
        
        # Memory
        mem = psutil.virtual_memory()
        metrics['memory'] = mem.percent
        metrics['memory_used'] = mem.used
        metrics['memory_total'] = mem.total
        metrics['memory_available'] = mem.available
        
        # Disk
        disk = psutil.disk_usage('/')
        metrics['disk'] = (disk.used / disk.total) * 100
        metrics['disk_used'] = disk.used
        metrics['disk_total'] = disk.total
        metrics['disk_free'] = disk.free
        
        # Load Average
        try:
            load_avg = psutil.getloadavg()
            metrics['load_1min'] = load_avg[0]
            metrics['load_5min'] = load_avg[1]
            metrics['load_15min'] = load_avg[2]
        except:
            metrics['load_1min'] = 0
            metrics['load_5min'] = 0
            metrics['load_15min'] = 0
        
        # Temperature
        try:
            temps = psutil.sensors_temperatures()
            if temps and 'coretemp' in temps:
                metrics['temperature'] = temps['coretemp'][0].current
            else:
                metrics['temperature'] = 0
        except:
            metrics['temperature'] = 0
        
        # Network
        try:
            net_io = psutil.net_io_counters()
            current_time = time.time()
            
            if self.prev_net_io and self.prev_time:
                time_delta = current_time - self.prev_time
                if time_delta > 0:
                    upload_rate = (net_io.bytes_sent - self.prev_net_io.bytes_sent) / time_delta
                    download_rate = (net_io.bytes_recv - self.prev_net_io.bytes_recv) / time_delta
                    metrics['net_upload'] = self._rate_to_human(upload_rate)
                    metrics['net_download'] = self._rate_to_human(download_rate)
                else:
                    metrics['net_upload'] = "0 B/s"
                    metrics['net_download'] = "0 B/s"
            else:
                metrics['net_upload'] = "0 B/s"
                metrics['net_download'] = "0 B/s"
                
            self.prev_net_io = net_io
            self.prev_time = current_time
        except:
            metrics['net_upload'] = "N/A"
            metrics['net_download'] = "N/A"
        
        return metrics
    
    def update_display(self, metrics):
        """Update the dashboard display"""
        # Add metrics to history
        self.cpu_history.append(metrics['cpu'])
        self.mem_history.append(metrics['memory'])
        self.disk_history.append(metrics['disk'])
        self.load_history.append(metrics['load_1min'])
        self.temp_history.append(metrics['temperature'])
        
        # Clear screen
        self._clear_screen()
        
        # Header
        print("🛡️  PRIVAWARE REAL-TIME SYSTEM MONITOR 🛡️")
        print("=" * 60)
        print(f"🕒 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()
        
        # CPU Section
        cpu_status = self._get_status_emoji(metrics['cpu'], self.cpu_threshold - 20, self.cpu_threshold)
        print(f"🖥️  CPU USAGE {cpu_status}")
        print(f"   {self._create_ascii_bar(metrics['cpu'])}")
        if len(self.cpu_history) > 1:
            print(f"   Trend: {self._create_sparkline(list(self.cpu_history))}")
        print(f"   Cores: {metrics['cpu_logical_cores']}")
        print()
        
        # Memory Section
        mem_status = self._get_status_emoji(metrics['memory'], self.mem_threshold - 15, self.mem_threshold)
        print(f"💾 MEMORY USAGE {mem_status}")
        print(f"   {self._create_ascii_bar(metrics['memory'])}")
        mem_used_gb = metrics['memory_used'] / (1024**3)
        mem_total_gb = metrics['memory_total'] / (1024**3)
        print(f"   Used: {mem_used_gb:.1f} GB / {mem_total_gb:.1f} GB")
        if len(self.mem_history) > 1:
            print(f"   Trend: {self._create_sparkline(list(self.mem_history))}")
        print()
        
        # Disk Section
        disk_status = self._get_status_emoji(metrics['disk'], self.disk_threshold - 10, self.disk_threshold, reverse=True)
        print(f"💿 DISK USAGE {disk_status}")
        print(f"   {self._create_ascii_bar(metrics['disk'])}")
        disk_used_gb = metrics['disk_used'] / (1024**3)
        disk_total_gb = metrics['disk_total'] / (1024**3)
        print(f"   Used: {disk_used_gb:.1f} GB / {disk_total_gb:.1f} GB")
        if len(self.disk_history) > 1:
            print(f"   Trend: {self._create_sparkline(list(self.disk_history))}")
        print()
        
        # Load Average
        load_avg = metrics['load_1min']
        load_status = self._get_status_emoji(load_avg, self.load_threshold - 0.5, self.load_threshold)
        print(f"⚡ LOAD AVERAGE {load_status}")
        print(f"   1 min:  {load_avg:.2f}")
        print(f"   5 min:  {metrics['load_5min']:.2f}")
        print(f"   15 min: {metrics['load_15min']:.2f}")
        if len(self.load_history) > 1:
            print(f"   Trend: {self._create_sparkline(list(self.load_history))}")
        print()
        
        # Temperature
        if metrics['temperature'] > 0:
            temp_status = self._get_status_emoji(metrics['temperature'], self.temp_threshold - 15, self.temp_threshold)
            print(f"🌡️  TEMPERATURE {temp_status}")
            print(f"   {metrics['temperature']:.1f}°C")
            if len(self.temp_history) > 1:
                print(f"   Trend: {self._create_sparkline(list(self.temp_history))}")
            print()
        
        # Network
        print(f"🌐 NETWORK ACTIVITY")
        print(f"   ↑ Upload: {metrics['net_upload']}")
        print(f"   ↓ Download: {metrics['net_download']}")
        print()
        
        # Footer
        print("=" * 60)
        print("🔄 Refreshing every 1 second | Press Ctrl+C to stop")
    
    def start_monitoring(self):
        """Start the enhanced real-time monitoring"""
        print("🚀 Starting PrivAware Enhanced Real-Time Monitor...")
        print("📊 Real-time dashboard with ASCII charts and graphs")
        time.sleep(1)
        
        try:
            while True:
                metrics = self.get_system_metrics()
                self.update_display(metrics)
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n\n🛑 Stopping PrivAware Enhanced Real-Time Monitor...")
            print("👋 Thank you for using PrivAware!")

# Function to run the enhanced dashboard
def run_enhanced_dashboard():
    """Run the enhanced real-time dashboard"""
    from rich.console import Console
    from rich.panel import Panel
    
    console = Console()
    
    console.print(Panel("🚀 Starting PrivAware Enhanced Real-Time System Monitor", style="bold blue"))
    console.print("📊 Real-time dashboard with ASCII charts and graphs")
    console.print("🔄 Updates every 1 second | Press Ctrl+C to stop")
    console.print("")
    
    dashboard = EnhancedSystemDashboard()
    dashboard.start_monitoring()
