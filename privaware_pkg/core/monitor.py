
"""
System Monitor: Tracks system health and anomalies.
"""
import os
import json
import shutil
import psutil

SETTINGS_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'config', 'settings.json'))

def load_settings():
	with open(SETTINGS_PATH, 'r') as f:
		return json.load(f)

class SystemMonitor:
	def __init__(self):
		self.settings = load_settings()
		monitor = self.settings.get('monitor', {})
		self.cpu_threshold = monitor.get('cpu_threshold', 90)
		self.memory_threshold = monitor.get('memory_threshold', 90)
		self.disk_threshold = monitor.get('disk_threshold', 90)

	def check_cpu(self):
		usage = psutil.cpu_percent(interval=1)
		return usage, usage > self.cpu_threshold

	def check_memory(self):
		mem = psutil.virtual_memory()
		usage = mem.percent
		return usage, usage > self.memory_threshold

	def check_disk(self):
		usage = shutil.disk_usage('/')
		percent = usage.used / usage.total * 100
		return percent, percent > self.disk_threshold

	def run_all(self):
		cpu, cpu_alert = self.check_cpu()
		mem, mem_alert = self.check_memory()
		disk, disk_alert = self.check_disk()
		return {
			'cpu': {'usage': cpu, 'alert': cpu_alert},
			'memory': {'usage': mem, 'alert': mem_alert},
			'disk': {'usage': disk, 'alert': disk_alert}
		}

if __name__ == "__main__":
	monitor = SystemMonitor()
	results = monitor.run_all()
	for k, v in results.items():
		print(f"{k.upper()} Usage: {v['usage']:.2f}% {'[ALERT]' if v['alert'] else ''}")

