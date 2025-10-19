# privaware_pkg/core/checks/check_ssh_hardening.py - FIXED VERSION
"""
Check SSH hardening settings.
This check verifies if SSH server settings are hardened against common attacks.
"""

# Import the necessary classes and helpers from the common models file
import os
from pathlib import Path
from ..config_models import ConfigCheck, run_command_simple

def check_ssh_hardening() -> ConfigCheck:
    """
    Check SSH hardening settings.

    This check examines the SSH server configuration file (/etc/ssh/sshd_config)
    for common security hardening settings such as:
    - Disabling root login
    - Disabling password authentication (favoring key-based auth)
    - Setting appropriate timeouts
    - Restricting protocols

    Returns:
        ConfigCheck: Result of the check including status (PASS/WARN/FAIL/UNKNOWN),
                     details about SSH configuration findings, and remediation info.
    """
    # Create the check object instance with the correct ID, description, and severity
    # Matching the ID and description from the KB file is important for consistency.
    # Severity is HIGH as per the KB file.
    check = ConfigCheck("ssh_hardening", "SSH hardening settings", "HIGH")

    # --- Logic adapted from the KB method ---
    
    # 1. Define the path to the SSH server configuration file
    ssh_config_path = "/etc/ssh/sshd_config"
    
    # 2. Check if the SSH config file exists
    if os.path.exists(ssh_config_path):
        try:
            # 3. Read the SSH configuration file content
            with open(ssh_config_path, "r") as f:
                content = f.read()
            
            # 4. Initialize lists to track issues and remediation commands
            issues = []
            remediation_commands = []

            # 5. Check for specific hardening settings

            # --- Check: PermitRootLogin ---
            # Look for lines that explicitly allow root login or use default (commented)
            # Secure setting: PermitRootLogin no
            if "PermitRootLogin yes" in content:
                issues.append("Root login explicitly allowed (PermitRootLogin yes)")
                remediation_commands.append("sudo sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config")
            elif "#PermitRootLogin" in content or "PermitRootLogin" not in content:
                # If it's commented out (#PermitRootLogin) or not present at all,
                # the default depends on the SSH version, but it's better to be explicit.
                # Treat as a potential issue.
                issues.append("Root login setting not explicitly disabled (relies on default/implicit setting)")
                remediation_commands.append("echo 'PermitRootLogin no' | sudo tee -a /etc/ssh/sshd_config")
            # If PermitRootLogin no is explicitly set, it's good. No action needed.

            # --- Check: PasswordAuthentication ---
            # Look for lines that enable password authentication.
            # Secure setting: PasswordAuthentication no (requires keys)
            if "PasswordAuthentication yes" in content:
                issues.append("Password authentication enabled (PasswordAuthentication yes)")
                remediation_commands.append("sudo sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config")
            elif "#PasswordAuthentication" in content or "PasswordAuthentication" not in content:
                # If it's commented out or not present, default might allow passwords.
                # Explicitly disable it.
                issues.append("Password authentication setting not explicitly disabled")
                remediation_commands.append("echo 'PasswordAuthentication no' | sudo tee -a /etc/ssh/sshd_config")
            # If PasswordAuthentication no is explicitly set, it's good.

            # --- Check: PermitEmptyPasswords ---
            # This should almost always be 'no'.
            if "PermitEmptyPasswords yes" in content:
                issues.append("Empty passwords permitted (PermitEmptyPasswords yes)")
                remediation_commands.append("sudo sed -i 's/^PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config")
            # If it's 'no', commented, or absent (default is 'no'), it's okay.

            # --- Check: Protocol (for older SSH versions) ---
            # Note: Protocol 2 is the default and only option in modern OpenSSH.
            # Including this check for completeness if dealing with older systems.
            if "Protocol 1" in content or "Protocol 1," in content:
                 issues.append("Insecure SSH protocol version 1 allowed")
                 remediation_commands.append("sudo sed -i 's/^Protocol.*/#&/' /etc/ssh/sshd_config && echo 'Protocol 2' | sudo tee -a /etc/ssh/sshd_config")
            # If Protocol 2 or absent (modern default), it's okay.

            # --- Check: X11Forwarding ---
            # Generally should be disabled unless explicitly needed.
            if "X11Forwarding yes" in content and "#X11Forwarding" not in content:
                 # If explicitly enabled and not commented out
                 issues.append("X11 forwarding enabled (X11Forwarding yes)")
                 remediation_commands.append("sudo sed -i 's/^X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config")
            # If X11Forwarding no, commented, or absent (default is no), it's okay.

            # --- Determine Final Status based on findings ---
            if issues:
                # Found one or more insecure SSH settings
                check.status = "FAIL"
                # Provide a concise summary of issues
                check.details = "; ".join(issues[:3]) # Show first 3 issues
                check.remediation_needed = True
                # Combine remediation commands into a single executable string
                # Append a command to restart the SSH service after changes
                all_remediation_commands = remediation_commands + ["sudo systemctl restart sshd"]
                # Clean up the command string to avoid shell syntax errors
                check.remediation_command = " && ".join(all_remediation_commands)
            else:
                # No insecure settings found based on checks performed
                check.status = "PASS"
                check.details = "SSH hardening settings OK (PermitRootLogin no, PasswordAuthentication no, etc.)"

        except PermissionError:
            # Cannot read the SSH config file, likely due to insufficient privileges
            check.status = "UNKNOWN"
            check.details = "Cannot read SSH config file (permission denied)"
            # Don't offer remediation that requires sudo in the command string itself.
        except Exception as e:
            # Unexpected error reading or processing the SSH config file
            check.status = "UNKNOWN"
            check.details = f"Cannot read SSH config: {e}"
    else:
        # SSH server configuration file not found
        # This might mean the SSH server is not installed or configured.
        check.status = "UNKNOWN"
        check.details = "SSH config file not found (SSH server may not be installed)"

    # Return the populated ConfigCheck object
    return check
