# privaware_pkg/core/checks/check_log_permissions.py
"""
Check log file and directory permissions.
This check verifies if system log files and directories have appropriate, secure permissions to prevent unauthorized access.
"""

# Import the necessary classes and helpers from the common models file
import os
from pathlib import Path
from ..config_models import ConfigCheck, run_command_simple

def check_log_permissions() -> ConfigCheck:
    """
    Check log file and directory permissions.

    This check verifies that critical system log directories and files
    (like /var/log, /var/log/auth.log, /var/log/syslog, etc.)
    have restrictive permissions to prevent unauthorized reading or modification.

    Returns:
        ConfigCheck: Result of the check including status (PASS/WARN/FAIL/UNKNOWN),
                     details about permission findings, and remediation info.
    """
    # Create the check object instance with the correct ID, description, and severity
    check = ConfigCheck("log_permissions", "Log permissions and rotation", "MEDIUM")

    # --- Define sensitive log paths to check ---
    # These are common system log paths that should have restricted access.
    log_paths_to_check = [
        # Main log directory
        "/var/log",
        # Critical individual log files
        "/var/log/auth.log",      # Authentication logs
        "/var/log/syslog",        # General system logs
        "/var/log/messages",      # General system logs (older systems/RHEL)
        "/var/log/secure",        # Security related logs (RHEL/CentOS)
        "/var/log/kern.log",      # Kernel logs
        "/var/log/mail.log",      # Mail server logs
        "/var/log/apache2",       # Apache web server logs (directory)
        "/var/log/nginx",         # Nginx web server logs (directory)
        "/var/log/mysql",         # MySQL database logs (directory)
        "/var/log/postgresql",    # PostgreSQL database logs (directory)
    ]

    # --- Logic to check permissions ---
    issues_found = []
    checked_count = 0

    for path_str in log_paths_to_check:
        path = Path(path_str)
        if path.exists():
            checked_count += 1
            try:
                stat_info = path.stat()
                # Get permissions (last 3 octal digits)
                mode = stat_info.st_mode & 0o777

                is_problematic = False
                reason = ""

                if path.is_dir():
                    # For log directories like /var/log, /var/log/apache2
                    # Should generally not be world-writable or world-readable.
                    # A common secure permission is 755 (rwxr-xr-x) or 750 (rwxr-x---).
                    # Flagging if "others" have write permission is a strong check.
                    # Also flagging if "others" have read permission might be too strict
                    # for some systems, but it's a good security practice.
                    # Let's flag if "others" have write permission as critical.
                    # Let's also flag if "others" have read permission as a warning-level issue.
                    # For this check, we'll flag world-write as FAIL, world-read as WARN.
                    # However, the check status is binary (PASS/WARN/FAIL).
                    # Let's prioritize flagging world-write as the main failure condition.
                    
                    if mode & 0o002: # Check if "others" have write permission
                        is_problematic = True
                        reason = f"Directory is world-writable (mode {oct(mode)})"
                    elif mode & 0o004: # Check if "others" have read permission (less critical but still a concern)
                         # Depending on policy, this might be a WARN or acceptable.
                         # For a stricter security posture, we'll treat it as a potential issue.
                         # Let's make this a warning-level detail in the message but not necessarily FAIL the check.
                         # The overall check status will be determined after the loop.
                         reason = f"Directory is world-readable (mode {oct(mode)})"

                elif path.is_file():
                    # For critical log files like /var/log/auth.log, /var/log/syslog
                    # Should be readable by admins but not by regular users.
                    # Standard permissions are often 640 (rw-r-----) or 600 (rw-------).
                    # Flag if group or others have write permissions.
                    # Flag if others have read permissions.
                    
                    if mode & 0o002: # World-writable
                        is_problematic = True
                        reason = f"File is world-writable (mode {oct(mode)})"
                    elif mode & 0o020: # Group-writable (might be okay if controlled, but often a concern)
                        # This is a nuanced area. Group-write might be intended.
                        # For a strict check, we'll flag it. A more sophisticated check
                        # might look at group membership.
                        reason = f"File is group-writable (mode {oct(mode)})"
                    elif mode & 0o004: # World-readable
                        # Similar to directories, world-read on log files is often undesirable.
                        reason = f"File is world-readable (mode {oct(mode)})"

                # Generic check for any sensitive path being world-writable (critical)
                # This overrides less critical findings for the same path.
                if (mode & 0o002): # If world-writable
                    is_problematic = True
                    reason = f"Path is world-writable (mode {oct(mode)}) [Critical]"

                if is_problematic or reason: # If there was any issue or detail worth noting
                    # Prepend path to the reason for clarity
                    full_reason = f"{path_str}: {reason}" if reason else f"{path_str}: Permission issue (mode {oct(mode)})"
                    issues_found.append(full_reason)

            except PermissionError:
                # Cannot stat the path, might be expected for some (e.g., /var/log/secure if user lacks perms)
                # Log it but don't necessarily fail the entire check unless many paths are unreadable.
                issues_found.append(f"{path_str}: Permission denied reading path.")
            except Exception as e:
                # Unexpected error reading path
                issues_found.append(f"{path_str}: Error checking path: {e}")

    # --- Determine Check Status ---
    if checked_count == 0:
        check.status = "UNKNOWN"
        check.details = "No log paths could be checked."
    elif issues_found:
        # Found one or more paths with potentially insecure permissions
        # Determine if any issues are critical (world-writable)
        critical_issues = [issue for issue in issues_found if "[Critical]" in issue or "world-writable" in issue]
        
        if critical_issues:
            check.status = "FAIL"
            check.details = f"Critical permission issues found on {len(critical_issues)} log path(s): {', '.join(critical_issues[:2])}..." # Show first 2 critical
        else:
            # Less critical issues (e.g., world-readable)
            check.status = "WARN"
            check.details = f"Permission issues found on {len(issues_found)} log path(s): {', '.join(issues_found[:3])}..." # Show first 3

        check.remediation_needed = True
        # Provide a generic remediation command. Specific fixes depend on the path and issue.
        # This command suggests using chmod to fix permissions.
        # Instruct the user to research correct permissions or use system tools.
        check.remediation_command = (
            "Use 'ls -l <path>' to see current permissions. "
            "Use 'sudo chmod <correct_permissions> <path>' to fix. "
            "Common secure permissions: "
            "Directories: 755 (rwxr-xr-x) or 750 (rwxr-x---); "
            "Files: 640 (rw-r-----) or 600 (rw-------). "
            "Example: sudo chmod 640 /var/log/auth.log"
        )
    else:
        # All checked paths have acceptable permissions (based on our checks)
        check.status = "PASS"
        check.details = f"Checked {checked_count} log paths. Permissions appear secure."

    # Return the populated ConfigCheck object
    return check
