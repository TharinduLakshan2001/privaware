# privaware_pkg/core/checks/check_disk_encryption.py
"""
Check full-disk encryption.
This check verifies if the root filesystem is encrypted using LUKS.
"""

import os
from pathlib import Path
from ..config_models import ConfigCheck, run_command_simple

def check_disk_encryption() -> ConfigCheck:
    """
    Check full-disk encryption.

    This check uses `lsblk -f` to look for filesystems formatted with crypto_LUKS,
    which indicates LUKS encryption.

    Returns:
        ConfigCheck: Result of the check including status, details, and remediation info.
    """
    # Create the check object instance
    check = ConfigCheck("disk_encryption", "Full-disk encryption", "CRITICAL")

    # Check if this check has been acknowledged
    ack_file = Path.home() / ".privaware" / "acknowledged" / "disk_encryption"
    if ack_file.exists():
        check.status = "PASS"
        check.details = "Full-disk encryption acknowledged by user"
        return check

    # --- Logic adapted from the KB method ---
    # Check for encrypted root filesystem using lsblk
    code, out, err = run_command_simple("lsblk -f")
    if code == 0:
        # Command succeeded, check the output
        if "crypto_LUKS" in out or "crypt" in out:
            # Encrypted filesystems (specifically LUKS) were found
            check.status = "PASS"
            check.details = "Encrypted filesystems detected (LUKS)"
        else:
            # No LUKS encrypted filesystems found
            check.status = "FAIL"
            check.details = "No encrypted filesystems found"
            # Disk encryption typically requires reinstallation to implement,
            # so the remediation is a descriptive message rather than a command.
            check.remediation_needed = True
            check.remediation_command = (
                "echo 'ACTION REQUIRED: Full disk encryption requires system reinstallation "
                "OR configuring an encrypted swapfile/partition if full reinstallation is not feasible.'"
            )
    else:
        # Command failed (e.g., lsblk not found, permission error)
        check.status = "UNKNOWN"
        check.details = f"Cannot check filesystems: {err}"

    # Return the populated ConfigCheck object
    return check
