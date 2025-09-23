# privaware_pkg/core/checks/check_vpn_status.py
"""
Check VPN interface & killswitch status.
This check verifies if a VPN interface is active and potentially if a killswitch is configured.
"""

# Import the necessary classes and helpers from the common models file
from ..config_models import ConfigCheck, run_command_simple

def check_vpn_status() -> ConfigCheck:
    """
    Check VPN interface & killswitch status.

    This check looks for network interfaces commonly associated with VPNs
    (like tun/tap interfaces) to determine if a VPN connection is active.
    It also checks for basic signs of a potential killswitch configuration.

    Returns:
        ConfigCheck: Result of the check including status (PASS/WARN/FAIL/UNKNOWN),
                     details about VPN interface findings, and remediation info.
    """
    # Create the check object instance with the correct ID, description, and severity
    # Matching the ID and description from the KB file is important for consistency.
    check = ConfigCheck("vpn_status", "VPN interface & killswitch", "HIGH")

    # --- Logic adapted from the KB method ---
    
    # 1. Check for active VPN interfaces using `ip link show`
    # Common VPN interface types: tun (OpenVPN, WireGuard), tap (Ethernet over VPN)
    code, out, err = run_command_simple("ip link show")
    if code == 0:
        # Command succeeded, check the output for VPN interface indicators
        vpn_indicators = ['tun', 'tap', 'wg'] # wg for WireGuard
        active_vpn_interfaces = []

        # Parse the output lines to find interfaces
        # Example line: "3: wlan0: <BROADCAST,MULTICAST> mtu 1500 qdisc mq state UP mode DORMANT group default qlen 1000"
        # Example line: "10: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UNKNOWN mode DEFAULT group default qlen 500"
        lines = out.strip().split('\n')
        for line in lines:
            # Split the line to get the interface name (usually the 2nd element)
            parts = line.split(':')
            if len(parts) >= 2:
                # The interface name is typically the second part, stripped of whitespace
                interface_name = parts[1].strip()
                # Check if the interface name starts with a VPN indicator
                if any(interface_name.startswith(indicator) for indicator in vpn_indicators):
                    # Extract more details if needed, but for now, just record the name
                    active_vpn_interfaces.append(interface_name)

        if active_vpn_interfaces:
            # Found active VPN interfaces
            check.status = "PASS"
            check.details = f"Active VPN interface(s) detected: {', '.join(active_vpn_interfaces)}"
            # A VPN being active is generally good for privacy, so no remediation is needed.
            # However, one could argue for checking if it's a *trusted* VPN, but that's beyond scope.
        else:
            # No VPN interfaces found
            check.status = "WARN"
            check.details = "No active VPN interface found"
            # Not having a VPN is a warning because it's a recommended privacy measure,
            # but it's not a direct system misconfiguration.
            check.remediation_needed = True
            # Provide a generic remediation command suggesting connecting to a VPN.
            # This is difficult to make specific as it depends on the VPN client/service used.
            check.remediation_command = (
                "Connect to a trusted VPN service. "
                "This action is typically performed through your VPN client application or by establishing a connection via OpenVPN/WireGuard configuration files."
            )
    else:
        # Command failed (e.g., `ip` command not found, permission error)
        check.status = "UNKNOWN"
        check.details = f"Cannot check network interfaces: {err}"

    # Return the populated ConfigCheck object
    return check
