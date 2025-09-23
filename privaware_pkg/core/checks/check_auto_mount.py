# privaware_pkg/core/checks/check_auto_mount.py
"""
Check auto-mount/automount disabled for removable media.
This check verifies if the system is configured to prevent automatic mounting of removable media.
"""

from ..config_models import ConfigCheck, run_command_simple # Import from the common models file

def check_auto_mount() -> ConfigCheck:
    """
    Check if auto-mount/automount is disabled for removable media.

    This check looks at common desktop environment settings (GNOME) to see if
    automatic mounting of media is enabled.

    Returns:
        ConfigCheck: Result of the check including status, details, and remediation info.
    """
    # Create the check object using the imported class
    check = ConfigCheck("auto_mount", "Auto-mount disabled", "MEDIUM")

    # --- Actual Check Logic (adapted from the KB method) ---
    # Check various auto-mount settings (GNOME specific)
    checks = [
        ("gsettings get org.gnome.desktop.media-handling automount", "false"),
        ("gsettings get org.gnome.desktop.media-handling automount-open", "false")
    ]

    auto_mount_enabled = False
    issues_found = []

    for cmd, expected_value in checks:
        try:
            # Use shell=True for gsettings as it's a command-line tool
            code, out, err = run_command_simple(cmd, shell=True) # Use the helper
            if code == 0:
                # Check if the actual output indicates the setting is ENABLED
                # The output for 'true' setting is usually just 'true'
                if 'true' in out.lower().strip():
                    auto_mount_enabled = True
                    issues_found.append(f"Setting '{cmd.split()[-1]}' is enabled (found: {out.strip()})")
                # If it's 'false' or '@as []' or '', it's likely disabled.
            else:
                # Command failed, might not be GNOME or gsettings unavailable
                issues_found.append(f"Could not check '{cmd.split()[-1]}': {err.strip()}")
        except Exception as e: # Catch broader exceptions
            issues_found.append(f"Error checking '{cmd.split()[-1]}': {str(e)}")

    # --- Determine Check Status ---
    if auto_mount_enabled:
        check.status = "WARN"
        check.details = "; ".join(issues_found) if issues_found else "Auto-mount is enabled for removable media"
        check.remediation_needed = True
        # Provide command to disable auto-mount
        check.remediation_command = (
            "gsettings set org.gnome.desktop.media-handling automount false && "
            "gsettings set org.gnome.desktop.media-handling automount-open false"
        )
    elif issues_found:
        # If we couldn't check the settings definitively
        check.status = "UNKNOWN"
        check.details = "; ".join(issues_found)
        # Don't mark remediation needed if we couldn't check
    else:
        # Auto-mount appears to be disabled or we couldn't find evidence it's enabled
        check.status = "PASS"
        check.details = "Auto-mount appears to be disabled for removable media"

    # Return the populated ConfigCheck object
    return check

# --- Important ---
# The function name MUST match the filename (without .py) for the dynamic loader
# in config_checker.py to find it correctly.
# check_auto_mount() function is in check_auto_mount.py
