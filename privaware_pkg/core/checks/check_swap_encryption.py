# privaware_pkg/core/checks/check_swap_encryption.py
"""
Check swap encryption or encrypted swapfile.
This check verifies if the system's swap space (partition or file) is encrypted.
"""

# Import the necessary classes and helpers from the common models file
from ..config_models import ConfigCheck, run_command_simple

def check_swap_encryption() -> ConfigCheck:
    """
    Check swap encryption or encrypted swapfile.

    This check uses `swapon --show` to list active swap spaces and
    determines if they are encrypted (indicated by 'crypto' or 'crypt' in the output).

    Returns:
        ConfigCheck: Result of the check including status (PASS/WARN/FAIL/UNKNOWN),
                     details about swap encryption findings, and remediation info.
    """
    # Create the check object instance with the correct ID, description, and severity
    # Matching the ID and description from the KB file is important for consistency.
    # Severity is HIGH as per the KB file.
    check = ConfigCheck("swap_encryption", "Swap encryption", "HIGH")

    # --- Logic adapted from the KB method ---
    
    # 1. Check for active swap spaces using `swapon --show`
    code, out, err = run_command_simple("swapon --show")
    if code == 0 and out:
        # Command succeeded and there is output (meaning swap is configured/active)
        
        # Check the output for indicators of encryption
        # The `swapon --show` command typically outputs something like:
        # NAME      TYPE      SIZE USED PRIO UUID                                 FILE
        # /dev/sda2 partition 2.0G   0B   -2 e1234567-89ab-cdef-0123-456789abcdef swap
        # Or for an encrypted swap:
        # NAME      TYPE      SIZE USED PRIO UUID                                 FILE
        # /dev/mapper/swap_crypt partition 2.0G   0B   -2 e1234567-89ab-cdef-0123-456789abcdef [crypt]
        
        if 'crypto' in out.lower() or 'crypt' in out.lower():
            # Found indicators of encrypted swap (e.g., [crypt], crypto_LUKS)
            check.status = "PASS"
            check.details = "Encrypted swap detected"
        else:
            # Swap is active but no encryption indicators found
            check.status = "FAIL"
            check.details = "Swap not encrypted"
            check.remediation_needed = True
            # Provide a remediation command. Note: Encrypting swap often requires
            # system configuration changes or re-installation, so the message reflects that.
            check.remediation_command = (
                "To encrypt swap, consider reconfiguring it: "
                "1. Turn off swap: sudo swapoff -a. "
                "2. Encrypt the swap partition/file (requires LUKS setup). "
                "3. Update /etc/fstab and /etc/crypttab. "
                "4. Re-enable swap: sudo swapon -a. "
                "Alternatively, ensure the system uses suspend-to-RAM only, not hibernate."
            )
    elif code == 0 and not out:
        # Command succeeded but no output means no swap is configured/active
        check.status = "UNKNOWN"
        check.details = "No swap configured or active"
        # This is not necessarily a failure. Systems without swap or with sufficient RAM
        # don't need swap. However, if swap is expected, its absence could be an issue.
        # For this check, we treat no swap as UNKNOWN.
    else:
        # Command failed (e.g., `swapon` not found, permission error)
        check.status = "UNKNOWN"
        check.details = f"Cannot check swap status: {err}"

    # Return the populated ConfigCheck object
    return check
