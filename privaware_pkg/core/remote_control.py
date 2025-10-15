
"""
Remote Control: Allows privileged users to control PrivAware via email commands.
"""
import os
import json
from dotenv import load_dotenv

SETTINGS_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'config', 'settings.json'))
ENV_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '.env'))

def load_settings():
	with open(SETTINGS_PATH, 'r') as f:
		return json.load(f)

def load_env():
	load_dotenv(ENV_PATH)
	return os.getenv('OWNER_EMAIL')

class RemoteControl:
	def __init__(self):
		self.settings = load_settings()
		self.enabled = self.settings.get('remote_control', {}).get('enabled', False)
		self.accepted_senders = self.settings.get('remote_control', {}).get('accepted_senders', [])
		self.owner_email = load_env()
		if self.owner_email and self.owner_email not in self.accepted_senders:
			self.accepted_senders.append(self.owner_email)

	def check_email_commands(self):
		if not self.enabled:
			print("[RemoteControl] Remote control is disabled in settings.")
			return
		# Placeholder: In production, connect to email inbox and parse commands
		print(f"[RemoteControl] Checking for commands from: {self.accepted_senders}")
		# Example: If a command is found, parse and execute it securely
		# This is a stub for demonstration

if __name__ == "__main__":
	rc = RemoteControl()
	rc.check_email_commands()
