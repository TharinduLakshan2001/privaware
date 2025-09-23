# privaware_pkg/core/checks/check_disk_encryption.py
"""
Check full-disk encryption.
This check verifies if the root filesystem is encrypted using LUKS.
"""

# Import the necessary classes and helpers from the common models file
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
    # The check_id should match the one used in the old monolithic file ("disk_encryption")
    # and the description/severity should also match.
    check = ConfigCheck("disk_encryption", "Full-disk encryption", "CRITICAL")

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
            # Disk encryption typically requires reinstallation to implement.
            # The remediation is a descriptive message.
            # FIXED: Provide a valid shell command (using echo) instead of plain text.
            check.remediation_needed = True
            check.remediation_command = (
                "echo '[ACTION REQUIRED] Full disk encryption requires system reinstallation "
                "OR configuring an encrypted swapfile/partition if full reinstallation is not feasible.'"
            )
    else:
        # Command failed (e.g., lsblk not found, permission error)
        check.status = "UNKNOWN"
        check.details = f"Cannot check filesystems: {err}"

    # Return the populated ConfigCheck object
    return check
