# privaware_pkg/core/checks/check_unauthorized_cron.py - FIXED VERSION
"""
Check for unauthorized cron/systemd timers (suspicious persistent tasks).
This check looks for cron jobs or systemd timers that might indicate malicious persistence.
"""

# Import the necessary classes and helpers from the common models file
import os
import subprocess
from pathlib import Path
from ..config_models import ConfigCheck, run_command_simple

def check_unauthorized_cron() -> ConfigCheck:
    """
    Check for unauthorized cron/systemd timers (suspicious persistent tasks).

    This check searches for cron jobs and systemd timers that contain
    suspicious keywords often associated with backdoors, reverse shells,
    or other malicious persistent mechanisms.

    Returns:
        ConfigCheck: Result of the check including status (PASS/WARN/FAIL/UNKNOWN),
                     details about suspicious cron/systemd entries found, and remediation info.
    """
    # Create the check object instance with the correct ID, description, and severity
    # Matching the ID and description from the KB file is important for consistency.
    # Severity is HIGH as per the KB file.
    check = ConfigCheck("unauthorized_cron", "Unauthorized cron/systemd timers", "HIGH")

    # --- Logic adapted from the KB method ---
    
    # 1. Define suspicious indicators (tools/phrases often used in malicious persistence)
    suspicious_indicators = [
        'nc', 'netcat', 'ncat',           # Network tools
        'wget', 'curl',                   # Download tools
        'bash', 'sh', 'python', 'perl',   # Scripting languages
        'reverse', 'backdoor', 'trojan',  # Obvious malicious terms
        'ssh', 'scp',                     # Remote access (when used in automated scripts)
        'base64', 'decode',               # Encoding/decoding (often used to obfuscate)
        'msf', 'meterpreter',             # Metasploit/Meterpreter specific
        'socat',                          # Another network tool
        'nohup',                          # Often used to keep processes running
        '/dev/tcp/', '/dev/udp/'          # Bash TCP redirection
    ]

    issues_found = []

    try:
        # --- 2. Check user crontabs ---
        # Get list of all users on the system
        code, out, err = run_command_simple("cat /etc/passwd | cut -d: -f1")
        if code == 0:
            users = out.split('\n')
            for user in users:
                user = user.strip()
                if user:
                    # Check individual user's crontab
                    # Suppress errors for users who don't have a crontab
                    code, out, err = run_command_simple(f"crontab -u {user} -l 2>/dev/null")
                    if code == 0 and out:
                        # Successfully read a crontab for this user
                        for line in out.split('\n'):
                            line = line.strip()
                            # Ignore comment lines and empty lines
                            if line and not line.startswith('#'):
                                # Check the line for any suspicious indicators
                                for indicator in suspicious_indicators:
                                    if indicator.lower() in line.lower():
                                        # Found a suspicious line
                                        # Truncate line for display if too long
                                        display_line = line[:100] + "..." if len(line) > 100 else line
                                        issues_found.append(f"User {user} cron: {display_line}")
                                        break # Stop checking other indicators for this line

        # --- 3. Check system-wide cron directories ---
        cron_dirs = [
            "/etc/cron.d",
            "/etc/cron.daily",
            "/etc/cron.hourly",
            "/etc/cron.monthly",
            "/etc/cron.weekly"
        ]
        
        for cron_dir_str in cron_dirs:
            cron_dir = Path(cron_dir_str)
            if cron_dir.exists():
                try:
                    # Iterate through files in the directory
                    for file_path in cron_dir.iterdir():
                        if file_path.is_file():
                            # Read the cron file content
                            try:
                                content = file_path.read_text()
                                for line in content.split('\n'):
                                    line = line.strip()
                                    # Ignore comment lines and empty lines
                                    if line and not line.startswith('#'):
                                        # Check the line for any suspicious indicators
                                        for indicator in suspicious_indicators:
                                            if indicator.lower() in line.lower():
                                                # Found a suspicious line
                                                display_line = line[:100] + "..." if len(line) > 100 else line
                                                issues_found.append(f"{cron_dir_str}/{file_path.name}: {display_line}")
                                                break # Stop checking other indicators for this line
                            except (PermissionError, IOError):
                                # Cannot read this specific file, continue to others
                                continue
                except PermissionError:
                    # Cannot list directory contents, continue to others
                    continue

        # --- 4. Check systemd timers for suspicious names or commands ---
        # Get list of active systemd timers
        code, out, err = run_command_simple("systemctl list-timers --all --no-pager")
        if code == 0:
            # Check timer descriptions and associated services
            for line in out.split('\n'):
                line_lower = line.lower()
                for indicator in suspicious_indicators:
                    if indicator in line_lower:
                        # Found a suspicious term in a timer listing
                        display_line = line[:150] + "..." if len(line) > 150 else line
                        issues_found.append(f"Systemd timer (suspicious): {display_line}")
                        break # Stop checking other indicators for this line
                        
        # Get a list of all systemd timer unit files
        code, out, err = run_command_simple("systemctl list-unit-files --type=timer --no-pager")
        if code == 0:
             # Check timer unit file names
             for line in out.split('\n'):
                 line_lower = line.lower()
                 for indicator in suspicious_indicators:
                     if indicator in line_lower:
                         # Found a suspicious term in a timer unit file name
                         display_line = line[:150] + "..." if len(line) > 150 else line
                         issues_found.append(f"Systemd timer unit file (suspicious): {display_line}")
                         break # Stop checking other indicators for this line

    except Exception as e:
        # An unexpected error occurred during the check
        check.status = "UNKNOWN"
        check.details = f"Cannot check cron/systemd: {e}"
        return check # Return early with UNKNOWN status

    # --- 5. Determine Final Check Status ---
    if issues_found:
        # Found one or more suspicious cron jobs or systemd timers
        check.status = "WARN"
        # Report the number of issues found and list the first few for details
        check.details = f"Found {len(issues_found)} suspicious cron/systemd entries: {', '.join(issues_found[:3])}..." # Show first 3
        check.remediation_needed = True
        # Provide a clean remediation command to investigate further.
        # Specific removal commands depend on the exact entry found.
        check.remediation_command = (
            "sudo ls -l /etc/cron.*"
        )
    else:
        # No suspicious entries found based on the indicators checked
        check.status = "PASS"
        check.details = "No suspicious cron/systemd timers found"

    # Return the populated ConfigCheck object
    return check
