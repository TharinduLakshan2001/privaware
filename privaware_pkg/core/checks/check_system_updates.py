# privaware_pkg/core/checks/check_system_updates.py
"""
Check for system updates and available security upgrades.
This check verifies if the system has pending updates, especially security-related ones.
"""

# Import the necessary classes and helpers from the common models file
from ..config_models import ConfigCheck, run_command_simple

def check_system_updates() -> ConfigCheck:
    """
    Check for system updates and available security upgrades.

    This check attempts to determine if there are pending system updates
    using the system's package manager (apt, yum, dnf, pacman).
    It prioritizes checking for security updates but falls back to general updates.

    Returns:
        ConfigCheck: Result of the check including status (PASS/WARN/FAIL/UNKNOWN),
                     details about update availability, and remediation info.
    """
    # Create the check object instance with the correct ID, description, and severity
    # Matching the ID and description from the KB file is important for consistency.
    # Severity is MEDIUM as per the KB file.
    check = ConfigCheck("system_updates", "System updates available", "MEDIUM")

    # --- Logic adapted from the KB method ---
    
    # 1. Try checking for updates using APT (Debian/Ubuntu)
    # This is often the most common package manager to encounter.
    
    # a. First, check if 'apt' command exists
    apt_exists_code, _, _ = run_command_simple("which apt")
    if apt_exists_code == 0:
        # 'apt' is available
        
        # b. Try to get a list of upgradable packages
        # This command requires privileges to access package databases/cache.
        # It might fail if run by a non-root user without proper setup (like apt-cache).
        # Using 'apt list --upgradable' is a good first attempt.
        upgradable_code, upgradable_out, upgradable_err = run_command_simple("apt list --upgradable 2>/dev/null")
        
        if upgradable_code == 0 and upgradable_out.strip():
            # Command succeeded and produced output
            # The output includes a header line like "Listing... Done" and then package lines.
            # Example lines:
            # Listing... Done
            # firefox/jammy-security,jammy-updates 102.5.0+build1-0ubuntu0.22.04.1 amd64 [upgradable from: 102.3.0+build1-0ubuntu0.22.04.1]
            # libpam-modules/jammy-security,jammy-updates 1.4.0-11ubuntu2.1 amd64 [upgradable from: 1.4.0-11ubuntu2]
            
            # Count the lines, subtracting 1 for the header.
            lines = upgradable_out.strip().split('\n')
            # Filter out lines that look like package entries (they usually have '/')
            package_lines = [line for line in lines if '/' in line and ' ' in line]
            upgradable_count = len(package_lines)
            
            if upgradable_count > 0:
                # There are packages that can be upgraded
                check.status = "WARN"
                check.details = f"{upgradable_count} system updates available"
                check.remediation_needed = True
                # Provide a remediation command to upgrade packages.
                # Note: This command will likely require sudo privileges to execute successfully.
                check.remediation_command = "sudo apt update && sudo apt upgrade -y"
                return check # Early return as we found updates
            else:
                # No upgradable packages found
                check.status = "PASS"
                check.details = "System is up to date (APT)"
                # Early return with PASS status
                return check
        
        # c. If 'apt list --upgradable' failed or produced no output,
        # try a simulation of an upgrade to see if anything would be done.
        # This is another way APT-based systems report pending updates.
        sim_upgrade_code, sim_upgrade_out, sim_upgrade_err = run_command_simple("apt-get -s upgrade")
        if sim_upgrade_code == 0 and sim_upgrade_out.strip():
            # Command succeeded, check the output for upgrade information
            # Look for lines indicating packages will be upgraded.
            # Example line: "123 upgraded, 0 newly installed, 0 to remove and 0 not upgraded."
            
            import re
            # Use regex to find the number of upgraded packages
            match = re.search(r'(\d+) upgraded', sim_upgrade_out)
            if match:
                upgrade_count = int(match.group(1))
                if upgrade_count > 0:
                    # Packages are available for upgrade
                    check.status = "WARN"
                    check.details = f"{upgrade_count} system updates available (simulated)"
                    check.remediation_needed = True
                    check.remediation_command = "sudo apt update && sudo apt upgrade -y"
                    return check # Early return
                else:
                    # Simulation shows no upgrades
                    check.status = "PASS"
                    check.details = "System is up to date (APT simulation)"
                    return check # Early return
        
        # d. If we reach here, APT commands ran but indicated no updates or failed in a way
        # that doesn't clearly indicate updates are available.
        # It's possible the user lacks permissions to check the package cache properly.
        # In this case, we report UNKNOWN as we cannot definitively determine the status.
        check.status = "UNKNOWN"
        check.details = "APT package manager detected but cannot check for updates (may need sudo or 'apt update')"
        # We don't offer a remediation command that requires sudo in the string itself.
        return check # Early return

    # 2. If APT is not available or checks were inconclusive, try other package managers
    
    # Check for YUM (older Red Hat/CentOS)
    yum_exists_code, _, _ = run_command_simple("which yum")
    if yum_exists_code == 0:
        # YUM is available
        # Note: 'yum check-update' returns exit code 100 if updates are available, 0 if not, non-zero for error.
        yum_code, yum_out, yum_err = run_command_simple("yum check-update")
        if yum_code == 100:
            # Updates are available
            # Count lines that look like package entries (usually have a repo name after a space)
            lines = (yum_out + yum_err).strip().split('\n') # YUM might put output in stderr
            # A rough count: lines with spaces (package name, version, repo)
            package_lines = [line for line in lines if line.strip() and ' ' in line and not line.startswith('Last metadata expiration')]
            update_count = len(package_lines)
            check.status = "WARN"
            check.details = f"YUM updates available ({update_count} packages listed)"
            check.remediation_needed = True
            check.remediation_command = "sudo yum update -y"
            return check # Early return
        elif yum_code == 0:
            # No updates available according to YUM
            check.status = "PASS"
            check.details = "System is up to date (YUM)"
            return check # Early return
        else:
            # YUM command failed
            check.status = "UNKNOWN"
            check.details = f"Cannot check YUM updates: exit code {yum_code}"
            return check # Early return

    # Check for DNF (newer Fedora/RHEL)
    dnf_exists_code, _, _ = run_command_simple("which dnf")
    if dnf_exists_code == 0:
        # DNF is available
        # Similar to YUM, 'dnf check-update' returns 100 for available updates, 0 for none, other for error.
        dnf_code, dnf_out, dnf_err = run_command_simple("dnf check-update")
        if dnf_code == 100:
            # Updates are available
            # Count package lines
            lines = (dnf_out + dnf_err).strip().split('\n')
            package_lines = [line for line in lines if line.strip() and ' ' in line and not line.startswith('Last metadata expiration')]
            update_count = len(package_lines)
            check.status = "WARN"
            check.details = f"DNF updates available ({update_count} packages listed)"
            check.remediation_needed = True
            check.remediation_command = "sudo dnf upgrade -y"
            return check # Early return
        elif dnf_code == 0:
            # No updates available according to DNF
            check.status = "PASS"
            check.details = "System is up to date (DNF)"
            return check # Early return
        else:
            # DNF command failed
            check.status = "UNKNOWN"
            check.details = f"Cannot check DNF updates: exit code {dnf_code}"
            return check # Early return

    # Check for Pacman (Arch Linux)
    pacman_exists_code, _, _ = run_command_simple("which pacman")
    if pacman_exists_code == 0:
        # Pacman is available
        # 'pacman -Qu' lists outdated packages.
        pacman_code, pacman_out, pacman_err = run_command_simple("pacman -Qu")
        if pacman_code == 0 and pacman_out.strip():
            # Outdated packages found
            lines = pacman_out.strip().split('\n')
            update_count = len([l for l in lines if l.strip()])
            check.status = "WARN"
            check.details = f"Pacman updates available ({update_count} packages)"
            check.remediation_needed = True
            check.remediation_command = "sudo pacman -Syu --noconfirm"
            return check # Early return
        elif pacman_code == 0:
            # No outdated packages
            check.status = "PASS"
            check.details = "System is up to date (Pacman)"
            return check # Early return
        else:
            # Pacman command failed
            check.status = "UNKNOWN"
            check.details = f"Cannot check Pacman updates: {pacman_err[:50]}..." # Truncate long errors
            return check # Early return

    # 3. If no recognized package manager was found or all checks were inconclusive
    check.status = "UNKNOWN"
    check.details = "No supported package manager found or cannot check for updates"
    # No specific remediation command can be provided without knowing the PM.

    # Return the final populated ConfigCheck object
    return check
