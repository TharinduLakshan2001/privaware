
"""
Utils: Helper functions shared across modules.
"""
import os
import json
import subprocess
import logging

def setup_logger(name='privaware', log_file='privaware.log', level=logging.INFO):
	formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
	handler = logging.FileHandler(log_file)
	handler.setFormatter(formatter)
	logger = logging.getLogger(name)
	logger.setLevel(level)
	if not logger.handlers:
		logger.addHandler(handler)
	return logger

def run_shell_command(cmd):
	try:
		result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
		return result.stdout.strip(), result.stderr.strip(), result.returncode
	except Exception as e:
		return '', str(e), 1

def load_json_config(path):
	try:
		with open(path, 'r') as f:
			return json.load(f)
	except Exception as e:
		print(f"[Utils] Failed to load config: {e}")
		return None
