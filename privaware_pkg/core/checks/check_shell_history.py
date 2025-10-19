# privaware_pkg/core/checks/check_shell_history.py - FIXED VERSION
"""
Check shell history protections.
This check verifies if shell history settings are configured to protect user privacy.
"""

# Import the necessary classes and helpers from the common models file
import os
from pathlib import Path
from ..config_models import ConfigCheck, run_command_simple

def check_shell_history() -> ConfigCheck:
    """
    Check shell history protections.

    This check verifies that shell history settings (like HISTSIZE, HISTFILE permissions)
    are configured to minimize privacy risks. It checks:
    - If HISTSIZE is set to 0 (disabling history).
    - If the history file has restrictive permissions (e.g., not world-readable).
    - General history file existence and basic sanity.

    Returns:
        ConfigCheck: Result of the check including status (PASS/WARN/FAIL/UNKNOWN),
                     details about history configuration findings, and remediation info.
    """
    # Create the check object instance with the correct ID, description, and severity
    # Matching the ID and description from the KB file is important for consistency.
    # Severity is LOW as per the KB file, reflecting it's a privacy enhancement.
    check = ConfigCheck("shell_history", "Shell history protections", "LOW")

    # --- Logic adapted from the KB method ---
    
    # 1. Check HISTSIZE environment variable
    # This is the primary check for disabling history.
    hist_size = os.environ.get('HISTSIZE', '') # Get HISTSIZE from the current environment
    
    # 2. Check HISTFILE environment variable
    # This tells us where the history file is located.
    hist_file_path_str = os.environ.get('HISTFILE', '') 
    
    issues_found = []
    
    # --- Evaluate HISTSIZE ---
    if hist_size:
        try:
            hist_size_int = int(hist_size)
            if hist_size_int != 0:
                # HISTSIZE is set but not to 0 (which disables history)
                issues_found.append(f"HISTSIZE={hist_size_int} (should be 0 for maximum privacy)")
            # If HISTSIZE is 0, it's good, do nothing.
        except ValueError:
            # HISTSIZE is not a valid integer, which is unusual but not necessarily bad.
            # It might be ignored by the shell. Flag it as a potential issue.
            issues_found.append(f"HISTSIZE is set to non-integer value '{hist_size}'")
    else:
        # HISTSIZE is not set. The default behavior depends on the shell.
        # For Bash, the default HISTSIZE is often 500 or 1000.
        # This means history is enabled by default.
        issues_found.append("HISTSIZE is not set (history is likely enabled by default)")

    # --- Evaluate HISTFILE permissions (if HISTFILE is set and points to an existing file) ---
    hist_file_issues = []
    if hist_file_path_str:
        hist_file_path = Path(hist_file_path_str)
        if hist_file_path.exists():
            try:
                hist_stat = hist_file_path.stat()
                # Get file permissions (last 3 octal digits)
                mode = hist_stat.st_mode & 0o777
                
                # Check permissions:
                # Ideally, the history file should only be readable/writable by the owner.
                # Standard secure permission is 600 (rw-------).
                # Flag if group or others have any permissions.
                
                # Check if "group" has any permissions (read, write, execute)
                if mode & 0o070: # Check middle digit (group permissions)
                    hist_file_issues.append(f"Group has permissions (mode {oct(mode)})")
                
                # Check if "others" have any permissions (read, write, execute)
                # This is the most critical privacy concern.
                if mode & 0o007: # Check last digit (other permissions)
                    hist_file_issues.append(f"World-accessible permissions (mode {oct(mode)})")
                    
                # A very common and acceptable permission is 600.
                # Anything that grants permissions beyond owner read/write is a potential issue.
                # For example, 644 (rw-r--r--) or 666 (rw-rw-rw-) are problematic.
                
            except PermissionError:
                # Cannot stat the history file, might be expected if it's in a protected location
                # or the user running the check doesn't own it.
                # This prevents us from checking permissions, but it might also mean
                # the file is protected.
                hist_file_issues.append("Permission denied reading history file permissions")
            except Exception as e:
                # Unexpected error checking history file
                hist_file_issues.append(f"Error checking history file permissions: {e}")
        else:
            # HISTFILE is set but the file doesn't exist (yet).
            # This is not necessarily an issue, the file will be created when the shell exits.
            # However, when it's created, its permissions will depend on the shell's default
            # and the user's umask. If umask is too permissive, the file could be created
            # with insecure permissions.
            # For now, we can't check the file itself, but we can note HISTFILE is set.
            # Let's not flag this as an issue, as the file simply hasn't been created yet.
            pass # Silently continue.
    else:
        # HISTFILE is not set in the environment.
        # The shell will likely use a default location (e.g., ~/.bash_history).
        # We cannot determine the file path or its permissions without making assumptions.
        # This is a limitation of checking via environment variables only.
        # The check focuses on explicit configurations.
        # Not having HISTFILE set is common default behavior.
        # Let's not flag this.
        pass # Silently continue.

    # Combine history file issues with general issues
    if hist_file_issues:
        issues_found.extend([f"History file ({hist_file_path_str}): {issue}" for issue in hist_file_issues])

    # --- Determine Final Check Status ---
    if issues_found:
        # Found one or more issues with shell history configuration
        check.status = "WARN"
        check.details = "; ".join(issues_found[:3]) # Show first 3 issues to keep details concise
        check.remediation_needed = True
        # Provide clean remediation commands to fix the issues.
        # The primary fix is setting HISTSIZE=0.
        # Fixing file permissions requires knowing the exact file path.
        remediation_commands = []
        if "HISTSIZE=" in check.details and "should be 0" in check.details:
            remediation_commands.append("echo 'export HISTSIZE=0' >> ~/.bashrc")
        
        # If the issue is about file permissions, suggest a generic chmod command.
        # This requires knowing the file, which we have from HISTFILE.
        if hist_file_path_str and ("permissions" in check.details or "World-accessible" in check.details):
            remediation_commands.append(f"chmod 600 {hist_file_path_str}")
            
        # If HISTSIZE is not set, suggest setting it.
        if "HISTSIZE is not set" in check.details:
             remediation_commands.append("echo 'export HISTSIZE=0' >> ~/.bashrc")

        if remediation_commands:
            check.remediation_command = " && ".join(remediation_commands)
        else:
            # Fallback remediation if specific commands weren't determined
            check.remediation_command = (
                "echo 'export HISTSIZE=0' >> ~/.bashrc && "
                "echo 'export HISTFILESIZE=0' >> ~/.bashrc"
            )
    else:
        # No issues found with shell history configuration based on checks performed
        # (HISTSIZE=0 and/or secure file permissions if file exists)
        check.status = "PASS"
        check.details = "Shell history is properly configured for privacy (HISTSIZE=0 or secure file permissions)"

    # Return the populated ConfigCheck object
    return check
