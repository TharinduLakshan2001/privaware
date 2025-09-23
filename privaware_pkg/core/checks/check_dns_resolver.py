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

    Returns:
        ConfigCheck: Result of the check including status, details, and remediation info.
    """
    # Create the check object instance
    check = ConfigCheck("dns_resolver", "DNS resolver configuration", "MEDIUM")

    # --- Logic adapted from the KB method ---
    try:
        # Check resolv.conf
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
                # Basic remediation command (adds Google DNS as an example)
                # In a production tool, this should be configurable or more robust.
                check.remediation_command = "echo 'nameserver 8.8.8.8' | sudo tee -a /etc/resolv.conf"
    except PermissionError:
        check.status = "UNKNOWN"
        check.details = "Cannot read /etc/resolv.conf (Permission denied)"
        # Don't offer remediation that requires sudo in the command string itself.
    except FileNotFoundError:
        check.status = "FAIL"
        check.details = "/etc/resolv.conf file not found"
        check.remediation_needed = True
        check.remediation_command = "touch /etc/resolv.conf && echo 'nameserver 8.8.8.8' | sudo tee /etc/resolv.conf"
    except Exception as e:
        check.status = "UNKNOWN"
        check.details = f"Cannot read /etc/resolv.conf: {e}"

    # Return the populated ConfigCheck object
    return check
