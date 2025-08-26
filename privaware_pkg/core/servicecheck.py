
"""
Service Monitor: Ensures critical services are running.
"""
import os
import json
import subprocess

SETTINGS_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'config', 'settings.json'))

def load_settings():
	with open(SETTINGS_PATH, 'r') as f:
		return json.load(f)

class ServiceChecker:
	def __init__(self):
		self.settings = load_settings()
		self.services = self.settings.get('servicecheck', {}).get('services', [])

	def check_service(self, service):
		# Try systemctl, fallback to service command
		try:
			result = subprocess.run(['systemctl', 'is-active', service], capture_output=True, text=True)
			if result.returncode == 0 and result.stdout.strip() == 'active':
				return True
		except Exception:
			pass
		try:
			result = subprocess.run(['service', service, 'status'], capture_output=True, text=True)
			if 'running' in result.stdout:
				return True
		except Exception:
			pass
		return False

	def check_all(self):
		status = {}
		for svc in self.services:
			status[svc] = self.check_service(svc)
		return status

if __name__ == "__main__":
	checker = ServiceChecker()
	results = checker.check_all()
	for svc, ok in results.items():
		print(f"{svc}: {'RUNNING' if ok else 'NOT RUNNING'}")
