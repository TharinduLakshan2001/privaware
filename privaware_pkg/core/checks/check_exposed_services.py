# privaware_pkg/core/checks/check_exposed_services.py
"""
Check exposed listening services.
This check verifies if services are exposed on all network interfaces (0.0.0.0 or :::).
"""

# Import the necessary classes and helpers from the common models file
from ..config_models import ConfigCheck, run_command_simple

def check_exposed_services() -> ConfigCheck:
    """
    Check for services listening on all public network interfaces.

    This check uses `ss -tuln` to list TCP and UDP sockets that are listening.
    It looks for services bound to `0.0.0.0:` (IPv4) or `:::` (IPv6), which means
    they accept connections on all available network interfaces, potentially exposing
    them publicly if the host has a public IP or is poorly firewalled.

    Returns:
        ConfigCheck: Result of the check including status (PASS/WARN/FAIL/UNKNOWN),
                     details about exposed services found, and remediation info.
    """
    # Create the check object instance with the correct ID and description
    # Matching the ID and description from the KB file is important for consistency.
    check = ConfigCheck("exposed_services", "Exposed listening services", "HIGH")

    # --- Logic adapted from the KB method ---
    # Check for services listening on all interfaces using ss (socket statistics)
    code, out, err = run_command_simple("ss -tuln") # -t tcp, -u udp, -l listening, -n numeric
    if code == 0:
        # Command succeeded, process the output
        exposed_services = []
        lines = out.split('\n')
        # Skip the header line ("State  Recv-Q  Send-Q  Local Address:Port  Peer Address:Port  Process")
        for line in lines[1:]:
            # A line representing a listening socket looks like:
            # LISTEN  0  128  0.0.0.0:22  0.0.0.0:*  users:(...)
            # LISTEN  0  128  [::]:22     [::]:*     users:(...)
            # We are interested in lines where Local Address is 0.0.0.0:<port> or [::]:<port>
            parts = line.split()
            if len(parts) >= 5 and parts[0] == "LISTEN":
                local_address_port = parts[4]
                # Check if it's bound to all IPv4 interfaces (0.0.0.0:port)
                # or all IPv6 interfaces ([::]:port)
                if local_address_port.startswith("0.0.0.0:") or local_address_port.startswith("[::]:"):
                     # Extract the port number (everything after the colon)
                     # For IPv6, it might be "[::]:22", so we split on ':' and take the last part.
                     # For IPv4, it's "0.0.0.0:22", same logic works.
                     try:
                         port = local_address_port.split(':')[-1]
                         # Basic validation that it's a number
                         int(port)
                         exposed_services.append(line.strip())
                     except (ValueError, IndexError):
                         # If port parsing fails, still count the line as exposed
                         # if the address part matches.
                         exposed_services.append(line.strip())

        if exposed_services:
            # Found services exposed on all interfaces
            check.status = "WARN" # Warn because exposure might be intentional, but it's a risk.
            check.details = f"Services exposed on all interfaces: {len(exposed_services)} found"
            check.remediation_needed = True
            # Provide a general remediation command. Specific fixes depend on the service.
            # This command suggests reviewing firewall rules or service configuration.
            check.remediation_command = (
                "Review firewall rules (e.g., ufw deny <port>) or "
                "reconfigure services to bind only to localhost (127.0.0.1 or ::1) if applicable. "
                "Use 'ss -tulnp' to see which process owns each socket."
            )
        else:
            # No services found listening on all interfaces
            check.status = "PASS"
            check.details = "No services exposed on all interfaces (0.0.0.0 or [::])"
    else:
        # Command failed (e.g., ss not found, permission error)
        check.status = "UNKNOWN"
        check.details = f"Cannot check listening services: {err}"

    # Return the populated ConfigCheck object
    return check
