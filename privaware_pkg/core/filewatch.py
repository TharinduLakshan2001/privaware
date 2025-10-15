
"""
File Watcher: Monitors sensitive files and directories for changes.
"""
import os
import json
import time
import hashlib

SETTINGS_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'config', 'settings.json'))

def load_settings():
	with open(SETTINGS_PATH, 'r') as f:
		return json.load(f)

def sha256sum(filename):
	h = hashlib.sha256()
	try:
		with open(filename, 'rb') as f:
			for chunk in iter(lambda: f.read(4096), b''):
				h.update(chunk)
		return h.hexdigest()
	except Exception:
		return None

class FileWatcher:
	def __init__(self, poll_interval=5):
		self.settings = load_settings()
		self.paths = self.settings.get('filewatch', {}).get('paths', [])
		self.poll_interval = poll_interval
		self.hashes = {}

	def initialize_hashes(self):
		for path in self.paths:
			expanded = os.path.expanduser(path)
			if os.path.isfile(expanded):
				self.hashes[expanded] = sha256sum(expanded)
			elif os.path.isdir(expanded):
				for root, dirs, files in os.walk(expanded):
					for file in files:
						fpath = os.path.join(root, file)
						self.hashes[fpath] = sha256sum(fpath)

	def watch(self):
		print("[FileWatcher] Monitoring for changes...")
		self.initialize_hashes()
		try:
			while True:
				for fpath in list(self.hashes.keys()):
					new_hash = sha256sum(fpath)
					if new_hash != self.hashes[fpath]:
						print(f"[FileWatcher] Change detected: {fpath}")
						self.hashes[fpath] = new_hash
				time.sleep(self.poll_interval)
		except KeyboardInterrupt:
			print("[FileWatcher] Stopped.")

if __name__ == "__main__":
	fw = FileWatcher()
	fw.watch()
