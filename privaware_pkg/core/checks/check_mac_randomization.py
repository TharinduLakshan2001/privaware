# privaware_pkg/core/checks/check_mac_randomization.py - FIXED VERSION
"""
Check Wi-Fi MAC address randomization.
This check verifies if MAC address randomization is enabled for Wi-Fi connections.
"""

# Import the necessary classes and helpers from the common models file
import os
from pathlib import Path
from ..config_models import ConfigCheck, run_command_simple

def check_mac_randomization() -> ConfigCheck:
    """
    Check Wi-Fi MAC address randomization.

    This check looks for configuration settings in NetworkManager or other
    network management tools that enable randomization of the Wi-Fi adapter's
    MAC address during scanning or connections. This helps prevent tracking.

    Returns:
        ConfigCheck: Result of the check including status (PASS/WARN/FAIL/UNKNOWN),
                     details about the configuration found, and remediation info.
    """
    # Create the check object instance with the correct ID, description, and severity
    # Matching the ID and description from the KB file is important for consistency.
    check = ConfigCheck("mac_randomization", "Wi-Fi MAC randomization", "MEDIUM")

    # --- Logic adapted and enhanced from the KB method ---
    
    # 1. Check NetworkManager configuration files
    # These are common locations where MAC randomization settings are configured.
    nm_config_paths = [
        "/etc/NetworkManager/NetworkManager.conf",
        "/etc/NetworkManager/conf.d/randomize-mac.conf",
        "/etc/NetworkManager/conf.d/default-wifi.scan-rand-mac-address.conf",
        "/usr/lib/NetworkManager/conf.d/90-default-wifi-scan-randomization.conf" # Read-only default
    ]
    
    mac_randomization_enabled = False
    config_files_checked = []
    found_in_file = None

    for config_path_str in nm_config_paths:
        config_path = Path(config_path_str)
        if config_path.exists():
            config_files_checked.append(config_path_str)
            try:
                # Read the configuration file content
                content = config_path.read_text()
                
                # Look for specific settings that enable MAC randomization
                # Modern NetworkManager uses 'wifi.scan-rand-mac-address=yes'
                # Older versions or custom configs might use 'cloned-mac-address=random'
                # The setting might be under a [device-mac-randomization] or [connection-mac-randomization] section
                # or a [device] section.
                
                # Check for the modern, recommended setting
                if 'wifi.scan-rand-mac-address=yes' in content:
                    mac_randomization_enabled = True
                    found_in_file = config_path_str
                    check.details = f"MAC randomization enabled via 'wifi.scan-rand-mac-address=yes' in {config_path_str}"
                    break # Found the strongest confirmation, exit loop
                
                # Check for older/common alternative settings
                elif 'cloned-mac-address=random' in content:
                    # This is often used within a connection profile or a specific section
                    # It's a good sign, but 'wifi.scan-rand-mac-address' is more specific for scanning.
                    mac_randomization_enabled = True
                    found_in_file = config_path_str
                    check.details = f"MAC randomization likely enabled via 'cloned-mac-address=random' in {config_path_str}"
                    # Don't break, keep looking for the stronger 'wifi.scan-rand-mac-address' confirmation
                
                # Check for a general enable directive (less specific)
                elif '[device-mac-randomization]' in content and 'wifi.scan-rand-mac-address=yes' in content:
                     # This combines section header and setting
                     mac_randomization_enabled = True
                     found_in_file = config_path_str
                     check.details = f"MAC randomization enabled in section in {config_path_str}"
                     break # Strong confirmation, exit loop

            except (PermissionError, IOError) as e:
                # Cannot read this specific file, continue checking others
                # Optionally log this specific failure if verbose mode is added later
                # For now, silently continue.
                pass

    # 2. If NM config files weren't conclusive, check the current runtime status (if nmcli is available)
    if not mac_randomization_enabled:
        # Try to query NetworkManager directly for the default scan behavior
        # This is a more definitive check but requires nmcli to be installed and accessible.
        nmcli_code, nmcli_out, nmcli_err = run_command_simple("nmcli -t -f GENERAL.WIFI-SYSTEM-SCAN-RAND-MAC-ADDRESS general")
        if nmcli_code == 0:
            # The output should be something like "GENERAL.WIFI-SYSTEM-SCAN-RAND-MAC-ADDRESS:yes"
            # or "GENERAL.WIFI-SYSTEM-SCAN-RAND-MAC-ADDRESS:no"
            output_lines = nmcli_out.strip().split('\n')
            for line in output_lines:
                 if line.startswith("GENERAL.WIFI-SYSTEM-SCAN-RAND-MAC-ADDRESS:"):
                     value = line.split(':', 1)[-1].strip().lower()
                     if value == 'yes':
                         mac_randomization_enabled = True
                         check.details = "MAC randomization confirmed active via runtime check (nmcli)."
                         # Append info about config files checked for context
                         if config_files_checked:
                             check.details += f" Config files checked: {', '.join(config_files[:2])}..."
                     elif value == 'no':
                         check.details = "MAC randomization confirmed inactive via runtime check (nmcli)."
                         if config_files_checked:
                             check.details += f" Config files checked: {', '.join(config_files[:2])}..."
                     else:
                         check.details = f"MAC randomization status unclear from nmcli: {value}"
                         if config_files_checked:
                             check.details += f" Config files checked: {', '.join(config_files[:2])}..."
                     break # Processed the relevant line
        else:
            # nmcli command failed, add info to details
            if config_files_checked:
                check.details = f"Config files checked: {', '.join(config_files_checked[:2])}... "
            else:
                check.details = "No standard NetworkManager config files found. "
            check.details += f"Cannot query runtime status (nmcli error: {nmcli_err[:30]}...)."


    # 3. Determine Final Check Status
    if mac_randomization_enabled:
        # MAC randomization is enabled/configured
        check.status = "PASS"
        # Details were set in the logic above
    else:
        # MAC randomization is not enabled or configuration couldn't be confirmed
        # Check if we found config files but they didn't enable it, or if no config files were found.
        if config_files_checked:
            # Config files exist, implying an attempt to manage NM, but randomization is not enabled.
            check.status = "WARN" # Or FAIL, depending on security policy. WARN allows for intentional disabling.
            # Details were partially set, finalize them.
            if not check.details:
                 check.details = f"NetworkManager config files found ({len(config_files_checked)} checked) but randomization not enabled."
        else:
            # No standard NM config files were found. This might mean:
            # a) A different network manager is used (unlikely for desktop Linux).
            # b) NM uses system/package-manager provided defaults (which might enable it).
            # c) NM is not installed/configured.
            # Without strong evidence, default to UNKNOWN or a conservative WARN.
            check.status = "WARN" # Conservative approach: warn that we cannot confirm it's ON.
            check.details = "No standard NetworkManager configuration files found to confirm MAC randomization status."

        # Mark for remediation as it's a recommended privacy setting.
        check.remediation_needed = True
        # Provide a clean remediation command
        check.remediation_command = (
            "sudo mkdir -p /etc/NetworkManager/conf.d && "
            "echo -e '[device]\\nwifi.scan-rand-mac-address=yes\\n\\n[connection]\\nwifi.cloned-mac-address=random' | "
            "sudo tee /etc/NetworkManager/conf.d/99-mac-randomization.conf && "
            "sudo systemctl reload NetworkManager"
        )

    # Return the populated ConfigCheck object
    return check
