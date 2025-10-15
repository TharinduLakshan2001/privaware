# privaware_pkg/core/checks/check_selinux_status.py
"""
Check SELinux/AppArmor status.
This check verifies if mandatory access control systems (SELinux or AppArmor) are active.
"""

# Import the necessary classes and helpers from the common models file
from ..config_models import ConfigCheck, run_command_simple

def check_selinux_status() -> ConfigCheck:
    """
    Check SELinux/AppArmor status.

    This check looks for active mandatory access control (MAC) systems like
    SELinux or AppArmor to enhance system security by restricting process capabilities.

    Returns:
        ConfigCheck: Result of the check including status (PASS/WARN/FAIL/UNKNOWN),
                     details about the MAC system found, and remediation info.
    """
    # Create the check object instance with the correct ID, description, and severity
    # Matching the ID and description from the KB file is important for consistency.
    # Severity is MEDIUM as per the KB file.
    check = ConfigCheck("selinux_status", "SELinux/AppArmor status", "MEDIUM")

    # --- Logic adapted from the KB method ---
    
    # 1. Check for AppArmor first (common on Ubuntu/Debian)
    # Use `aa-status --enabled` which returns 0 if the AppArmor subsystem is enabled.
    aa_code, aa_out, aa_err = run_command_simple("aa-status --enabled")
    if aa_code == 0:
        # AppArmor is active and enabled
        check.status = "PASS"
        check.details = "AppArmor Mandatory Access Control is active"
        return check # Early return as AppArmor is the preferred check result

    # 2. If AppArmor check failed or wasn't found, check for SELinux
    # Use `sestatus` which provides detailed SELinux status information.
    se_code, se_out, se_err = run_command_simple("sestatus")
    if se_code == 0:
        # `sestatus` command ran successfully, parse the output
        # Look for lines indicating SELinux is enabled
        # Example output lines:
        # SELinux status:                 enabled
        # SELinuxfs mount:                /sys/fs/selinux
        # SELinux root directory:         /etc/selinux
        # Loaded policy name:             targeted
        # Current mode:                   enforcing
        # Mode from config file:         enforcing
        # Policy MLS status:              enabled
        # Policy deny_unknown status:     allowed
        # Max kernel policy version:      31

        if "SELinux status:" in se_out and "enabled" in se_out:
            # SELinux is enabled
            check.status = "PASS"
            check.details = "SELinux Mandatory Access Control is active"
            return check # Early return as SELinux is active

    # 3. If neither AppArmor nor SELinux are confirmed active
    # The check could not verify an active MAC system.
    check.status = "WARN"
    check.details = "No active Mandatory Access Control system (AppArmor, SELinux) detected"
    
    # Determine if remediation is needed/warranted.
    # While having a MAC is highly recommended for security, the absence isn't
    # always a direct system misconfiguration that can be fixed with a simple command.
    # Enabling AppArmor/SELinux often requires system configuration/reboot and policy setup.
    check.remediation_needed = True
    
    # Provide remediation commands to install and enable common MAC systems.
    # Installing AppArmor is often simpler and well-integrated on Debian/Ubuntu.
    # Installing SELinux is more involved.
    check.remediation_command = (
        "To enable AppArmor (if available but not active): "
        "sudo apt install apparmor apparmor-utils && "
        "sudo systemctl enable apparmor && "
        "sudo systemctl start apparmor. "
        "Note: Enabling MAC systems requires careful configuration and may impact system functionality. "
        "Consult distribution-specific documentation for AppArmor or SELinux setup."
    )

    # Return the final populated ConfigCheck object
    return check
