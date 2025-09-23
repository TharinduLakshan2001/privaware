# privaware_pkg/core/checks/check_firewall.py
"""
Check firewall status.
This check verifies if a firewall (UFW, iptables, nftables) is active and configured.
"""

# Import the necessary classes and helpers from the common models file
from ..config_models import ConfigCheck, run_command_simple

def check_firewall() -> ConfigCheck:
    """
    Check firewall status.

    This check looks for active firewall software like UFW, iptables, or nftables.
    It prioritizes UFW, then iptables, then nftables for reporting status.

    Returns:
        ConfigCheck: Result of the check including status (PASS/WARN/FAIL/UNKNOWN),
                     details about the finding, and a precise remediation command.
    """
    # Create the check object instance
    check = ConfigCheck("firewall_active", "Firewall active & default policy", "HIGH")

    # --- 1. Check UFW (Uncomplicated Firewall) ---

    # a. Check if UFW service is active/enabled
    service_code, service_out, service_err = run_command_simple("systemctl is-active ufw")
    is_service_active = (service_code == 0 and service_out.strip() == "active")

    # b. Check UFW status command
    status_code, status_out, status_err = run_command_simple("ufw status")
    is_rules_active = (status_code == 0 and "Status: active" in status_out)

    # c. Check if UFW is enabled at boot
    enabled_code, enabled_out, enabled_err = run_command_simple("systemctl is-enabled ufw")
    is_enabled_at_boot = (enabled_code == 0 and enabled_out.strip() == "enabled")

    if is_service_active or is_rules_active or is_enabled_at_boot:
        # UFW is present and likely active/configured
        check.status = "PASS"
        # Provide details on what was checked
        details_parts = []
        if is_rules_active:
            details_parts.append("UFW rules active")
        if is_service_active:
            details_parts.append("UFW service active")
        if is_enabled_at_boot:
            details_parts.append("UFW enabled at boot")
        check.details = "; ".join(details_parts) if details_parts else "UFW is configured"
        # If UFW is not active but configured, remediation is to enable it.
        if not is_rules_active: # UFW is installed/configured but not running
             check.status = "FAIL" # Or WARN, depending on policy. FAIL forces fix.
             check.details += " (but currently inactive)"
             check.remediation_needed = True
             # Provide the precise command to enable it.
             check.remediation_command = "ufw --force enable" # --force avoids interactive prompt
        return check

    # --- 2. If UFW check failed or wasn't found, check iptables ---
    iptables_code, iptables_out, iptables_err = run_command_simple("iptables -L")
    if iptables_code == 0 and iptables_out:
        # Command succeeded and produced output (rules exist)
        # This is a weaker positive than UFW 'active'
        check.status = "WARN"
        check.details = "iptables rules are present, but service status is unclear. Verify if iptables-persistent is managing them."
        # Offer remediation to ensure iptables rules are persistent and UFW is considered.
        # Prioritize enabling UFW if it's available, as it's simpler.
        # Check if UFW is installed first.
        ufw_installed_code, _, _ = run_command_simple("which ufw")
        if ufw_installed_code == 0:
            # UFW is installed, recommend enabling it as the fix.
            check.remediation_needed = True
            # Provide the precise command to enable UFW.
            check.remediation_command = "ufw --force enable" # --force avoids interactive prompt
        else:
            # UFW not installed. Suggest installing and enabling it, or ensuring iptables persistence.
            # This is a bit more complex. For auto-fix, stick to enabling UFW if possible.
            # We can provide a command that tries UFW enable (will fail if not installed)
            # or falls back, but that's complex in a single shell command.
            # Let's provide the primary recommendation: install and enable UFW.
            # The auto-fix might fail if UFW needs installing, but the command is clear.
            check.remediation_needed = True
            # Provide the precise command chain. This will fail on the first part if UFW isn't installed,
            # but the user/sysadmin gets the idea.
            # A more robust fix would involve checking installation first, but for a command string...
            check.remediation_command = "apt-get update && apt-get install -y ufw && ufw --force enable"
        return check # Return based on iptables findings

    # --- 3. If iptables check failed or no rules, check nftables ---
    nft_code, nft_out, nft_err = run_command_simple("nft list rulesets")
    if nft_code == 0 and nft_out:
        # Command succeeded and listed rulesets
        check.status = "WARN"
        check.details = "nftables rulesets are present, but service status is unclear. Verify if nftables service is active."
        check.remediation_needed = True
        # Similar to iptables, suggest ensuring the service is active or moving to UFW.
        # Recommend enabling nftables service. This is a single command.
        check.remediation_command = "systemctl enable nftables && systemctl start nftables"
        return check # Return based on nftables findings

    # --- 4. If none of the specific checks clearly indicate an active firewall ---
    check.status = "FAIL"
    check.details = (
        "No active or configured firewall detected (UFW, iptables, nftables). "
        "The system is potentially exposed to network-based attacks."
    )
    check.remediation_needed = True
    # Provide a common, recommended remediation: install and enable UFW.
    # This is a clear, executable command chain.
    check.remediation_command = "apt-get update && apt-get install -y ufw && ufw --force enable"

    # Return the final ConfigCheck object
    return check
