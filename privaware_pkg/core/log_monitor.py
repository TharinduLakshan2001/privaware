
"""
Log Monitor: Parses logs for suspicious activity.
"""

import os
import json
import re
from .alerts import AlertSender

SETTINGS_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'config', 'settings.json'))

def load_settings():
	with open(SETTINGS_PATH, 'r') as f:
		return json.load(f)

class LogMonitor:
	def __init__(self):
		self.settings = load_settings()
		self.log_files = self.settings.get('log_monitor', {}).get('log_files', [])
		self.suspicious = self.settings.get('log_monitor', {}).get('suspicious_activity', [])

	def parse_logs(self, send_alerts=True):
		patterns = {
			'failed_logins': re.compile(r'Failed password'),
			'brute_force_attempts': re.compile(r'authentication failure|maximum authentication attempts'),
			'sudo_abuse': re.compile(r'sudo:|sudoers|session opened for user root|su:')
		}
		results = {k: [] for k in self.suspicious}
		alert_sender = AlertSender()
		for log_file in self.log_files:
			if not os.path.exists(log_file):
				continue
			with open(log_file, 'r', errors='ignore') as f:
				for line in f:
					for activity in self.suspicious:
						if activity in patterns and patterns[activity].search(line):
							results[activity].append(line.strip())
							# Send alert for root access or sudo abuse
							if send_alerts and activity in ['sudo_abuse']:
								alert_sender.send_alert(
									subject="PrivAware Alert: Root Access Attempt Detected",
									message=f"Suspicious root access or sudo activity detected:\n{line.strip()}"
								)
		return results

if __name__ == "__main__":
	monitor = LogMonitor()
	results = monitor.parse_logs()
	for activity, lines in results.items():
		print(f"\n=== {activity} ===")
		if lines:
			for l in lines:
				print(l)
		else:
			print("No suspicious activity found.")
