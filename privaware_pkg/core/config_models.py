# privaware_pkg/core/config_models.py
"""
Data models for configuration checks.
"""
from datetime import datetime

class ConfigCheck:
    def __init__(self, check_id: str, description: str, severity: str = "MEDIUM"):
        self.check_id = check_id
        self.description = description
        self.severity = severity
        self.status = "UNKNOWN"  # PASS, WARN, FAIL, UNKNOWN
        self.details = ""
        self.remediation_needed = False
        self.remediation_attempted = False
        self.remediation_result = ""
        self.remediation_command = ""  # Store the command to fix the issue

    def to_dict(self):
        return {
            'check_id': self.check_id,
            'description': self.description,
            'status': self.status,
            'severity': self.severity,
            'details': self.details,
            'remediation_needed': self.remediation_needed,
            'remediation_attempted': self.remediation_attempted,
            'remediation_result': self.remediation_result,
            'remediation_command': self.remediation_command,
            'timestamp': datetime.now().isoformat()
        }

# Optionally, define a helper for running commands if needed by checks
# This avoids each check needing to reimplement subprocess logic
def run_command_simple(command: str, shell=False, timeout=10) -> tuple:
    """Simple helper to run system commands."""
    import subprocess
    try:
        if shell:
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=timeout)
        else:
            result = subprocess.run(command.split(), capture_output=True, text=True, timeout=timeout)
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except Exception as e:
        return -1, "", str(e)
