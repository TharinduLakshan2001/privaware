# privaware_pkg/core/checks/check_folder_file_permissions.py - FIXED VERSION
"""
Check folder and file permissions.
This check verifies if sensitive system folders/files have appropriate, secure permissions.
"""

# Import the necessary classes and helpers from the common models file
import os
from pathlib import Path
from ..config_models import ConfigCheck, run_command_simple

def check_folder_file_permissions() -> ConfigCheck:
    """
    Check folder and file permissions for sensitive system paths.

    This check verifies that critical system directories and files
    (like /etc, /bin, /sbin, /usr/bin, /usr/sbin, root's home, etc.)
    have restrictive permissions to prevent unauthorized access or modification.

    Returns:
        ConfigCheck: Result of the check including status (PASS/WARN/FAIL/UNKNOWN),
                     details about permission findings, and remediation info.
    """
    # Create the check object instance
    # Using a descriptive check_id and matching the severity from typical standards.
    check = ConfigCheck("folder_file_permissions", "Folder and file permissions", "HIGH")

    # --- Define sensitive paths to check ---
    # These are common system paths that should have strict permissions.
    sensitive_paths = [
        # System directories
        "/etc",
        "/bin",
        "/sbin",
        "/usr/bin",
        "/usr/sbin",
        # Root's home directory is highly sensitive
        "/root",
        # Boot directory contains kernel images
        "/boot",
        # System configuration files
        "/etc/passwd",
        "/etc/shadow",
        "/etc/group",
        "/etc/gshadow",
        # SSH configuration and keys are critical
        "/etc/ssh",
        # If UFW is used, its configuration
        "/etc/ufw",
        # If AppArmor profiles exist
        "/etc/apparmor.d"
    ]

    # --- Logic to check permissions ---
    issues_found = []
    checked_count = 0

    for path_str in sensitive_paths:
        path = Path(path_str)
        if path.exists():
            checked_count += 1
            try:
                stat_info = path.stat()
                # Get permissions (last 3 octal digits)
                mode = stat_info.st_mode & 0o777
                
                # --- Define expected secure permissions ---
                # These are general guidelines. Exact requirements can vary.
                # The check will flag permissions that are too permissive.
                expected_perms = None
                is_problematic = False
                reason = ""

                if path.is_dir():
                    # For directories like /etc, /bin, /sbin, /usr/bin, /usr/sbin
                    if path_str in ["/etc", "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/boot"]:
                        # Should generally not be world-writable.
                        # Owner: rwx, Group: rx, Others: rx (755) is common,
                        # but checking for world-write is a key red flag.
                        if mode & 0o002: # Check if "others" have write permission
                            is_problematic = True
                            reason = f"Directory is world-writable (mode {oct(mode)})"
                        # Owner: rwx, Group: rx, Others: r (755) might also be acceptable
                        # depending on policy, but 755 is standard.
                        # A stricter check could enforce 755 or 750.
                        # For now, flagging world-write is a strong indicator.
                    
                    # Root's home directory
                    elif path_str == "/root":
                        # Should be very restrictive. Often 700 or 750.
                        # Flag if group or others have write/read permissions.
                        # Let's flag if "others" have any permissions as a strong check.
                        if mode & 0o077: # Check if group or others have any permissions
                             is_problematic = True
                             reason = f"Root directory has group/other permissions (mode {oct(mode)})"

                    # /etc/ssh directory
                    elif path_str == "/etc/ssh":
                        # Should be restrictive, often 755 or 750.
                        # Flag if world-writable.
                        if mode & 0o002:
                            is_problematic = True
                            reason = f"SSH directory is world-writable (mode {oct(mode)})"

                elif path.is_file():
                    # For critical files like passwd, shadow
                    if path_str in ["/etc/passwd"]:
                        # Should be readable by all but only writable by root (owner).
                        # Standard is usually 644. Flag if not.
                        # A strong check is ensuring it's not world-writable.
                        if mode & 0o002:
                            is_problematic = True
                            reason = f"passwd file is world-writable (mode {oct(mode)})"
                    
                    elif path_str in ["/etc/shadow", "/etc/gshadow"]:
                        # Should be extremely restrictive. Only root should read/write.
                        # Standard is 640 or 600. Flag if group/others have any permissions.
                        if mode & 0o077:
                            is_problematic = True
                            reason = f"{path.name} file has group/other permissions (mode {oct(mode)})"
                    
                    elif path_str in ["/etc/group"]:
                         # Should be readable by all but only writable by root (owner).
                         # Standard is usually 644. Flag if world-writable.
                         if mode & 0o002:
                             is_problematic = True
                             reason = f"group file is world-writable (mode {oct(mode)})"

                # Generic check for any sensitive path being world-writable
                # This is a strong, general security principle.
                if not is_problematic and (mode & 0o002):
                    # If not already flagged by specific rules, but is world-writable,
                    # it's still a concern.
                    is_problematic = True
                    reason = f"Path is world-writable (mode {oct(mode)}) [Generic Check]"

                if is_problematic:
                    issues_found.append(f"{path_str}: {reason}")

            except PermissionError:
                # Cannot stat the path, might be expected for some (e.g., /etc/shadow)
                # Log it but don't necessarily fail the entire check.
                # If MANY paths are unreadable, might warrant UNKNOWN.
                # For now, just note it if debugging.
                # issues_found.append(f"Permission denied reading {path_str}")
                pass # Silently skip permission errors for individual paths
            except Exception as e:
                # Unexpected error reading path
                issues_found.append(f"Error checking {path_str}: {e}")

    # --- Determine Check Status ---
    if checked_count == 0:
        check.status = "UNKNOWN"
        check.details = "No sensitive paths could be checked."
    elif issues_found:
        # Found one or more paths with insecure permissions
        check.status = "FAIL"
        check.details = f"Insecure permissions found on {len(issues_found)} path(s): {', '.join(issues_found[:3])}..." # Show first 3
        check.remediation_needed = True
        # Provide a proper remediation command with correct shell syntax
        check.remediation_command = (
            "chmod 640 /etc/shadow && chmod 640 /etc/gshadow && "
            "chmod 700 /root && chmod 644 /etc/passwd && chmod 644 /etc/group"
        )
    else:
        # All checked paths have acceptable permissions (based on our checks)
        check.status = "PASS"
        check.details = f"Checked {checked_count} sensitive paths. Permissions appear secure."

    # Return the populated ConfigCheck object
    return check
