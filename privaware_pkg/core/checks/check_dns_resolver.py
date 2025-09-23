# privaware_pkg/core/checks/check_dns_resolver.py
"""
Check DNS resolver configuration.
This check verifies if DNS resolvers are properly configured in /etc/resolv.conf.
"""

# Import the necessary classes and helpers from the common models file
from ..config_models import ConfigCheck, run_command_simple

def check_dns_resolver() -> ConfigCheck:
    """
    Check DNS resolver configuration.

    This check reads /etc/resolv.conf to verify if DNS nameservers are configured.
    It also checks if systemd-resolved is active as an alternative.

    Returns:
        ConfigCheck: Result of the check including status, details, and remediation info.
    """
    # Create the check object instance
    check = ConfigCheck("dns_resolver", "DNS resolver configuration", "MEDIUM")

    # --- Logic adapted from the KB method ---
    try:
        # First, check if systemd-resolved is active (more modern approach)
        systemd_resolved_code, systemd_resolved_out, systemd_resolved_err = run_command_simple("systemctl is-active systemd-resolved")
        if systemd_resolved_code == 0 and systemd_resolved_out.strip() == "active":
            # systemd-resolved is active, check its status
            resolvectl_code, resolvectl_out, resolvectl_err = run_command_simple("resolvectl status")
            if resolvectl_code == 0 and ("DNS Servers:" in resolvectl_out or "nameserver" in resolvectl_out):
                check.status = "PASS"
                check.details = "DNS configured via systemd-resolved"
                return check
            # If resolvectl fails or shows no servers, fall through to check /etc/resolv.conf

        # Check traditional /etc/resolv.conf
        with open("/etc/resolv.conf", "r") as f:
            content = f.read()
            if "nameserver" in content:
                check.status = "PASS"
                # Provide a snippet of the config in details
                check.details = f"DNS configured: {content[:100]}..." if len(content) > 100 else f"DNS configured: {content.strip()}"
            else:
                check.status = "FAIL"
                check.details = "No DNS nameservers configured in /etc/resolv.conf"
                check.remediation_needed = True
                # Safer remediation command: backup first, then append
                # This is safer than overwriting and provides a recovery option
                check.remediation_command = (
                    "sudo cp /etc/resolv.conf /etc/resolv.conf.backup.privaware && "
                    "echo 'nameserver 8.8.8.8' | sudo tee -a /etc/resolv.conf >/dev/null && "
                    "echo 'nameserver 8.8.4.4' | sudo tee -a /etc/resolv.conf >/dev/null"
                )
    except PermissionError:
        check.status = "UNKNOWN"
        check.details = "Cannot read /etc/resolv.conf (Permission denied)"
        # Don't offer remediation that requires sudo in the command string itself.
    except FileNotFoundError:
        check.status = "FAIL"
        check.details = "/etc/resolv.conf file not found"
        check.remediation_needed = True
        # Safer remediation: create the file with backup logic
        check.remediation_command = (
            "sudo touch /etc/resolv.conf && "
            "sudo chmod 644 /etc/resolv.conf && "
            "echo 'nameserver 8.8.8.8' | sudo tee /etc/resolv.conf >/dev/null && "
            "echo 'nameserver 8.8.4.4' | sudo tee -a /etc/resolv.conf >/dev/null"
        )
    except Exception as e:
        check.status = "UNKNOWN"
        check.details = f"Cannot read /etc/resolv.conf: {e}"

    # Return the populated ConfigCheck object
    return check
