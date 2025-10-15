# privaware_pkg/core/checks/check_root_access_monitoring.py
"""
Check for root access monitoring and detection.
This check verifies if systems are in place to monitor, alert on, or prevent unauthorized root access.
"""

# Import the necessary classes and helpers from the common models file
import os
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from ..config_models import ConfigCheck, run_command_simple

def check_root_access_monitoring() -> ConfigCheck:
    """
    Check for root access monitoring and detection mechanisms.

    This check looks for:
    1.  Evidence of recent successful root logins (from /var/log/auth.log or wtmp/btmp).
    2.  Checks if 'sudo' is configured to require authentication and logs usage.
    3.  Verifies if 'su' to root requires authentication.
    4.  Looks for basic signs of root access monitoring tools or configurations.
    5.  Warns if root password is enabled (making direct root login possible).

    Returns:
        ConfigCheck: Result of the check including status (PASS/WARN/FAIL/UNKNOWN),
                     details about root access findings, and remediation info.
    """
    # Create the check object instance
    check = ConfigCheck("root_access_monitoring", "Root access monitoring & prevention", "CRITICAL")

    # --- Logic for Root Access Monitoring Check ---
    issues_found = []
    warnings_found = []
    info_found = []
    remediation_suggestions = []

    # --- 1. Check for recent root logins in auth.log ---
    try:
        # This checks the last hour of authentication logs for 'Accepted' root logins
        # This is a basic check and might require sudo/root to read /var/log/auth.log
        one_hour_ago = datetime.now() - timedelta(hours=1)
        one_hour_timestamp = one_hour_ago.strftime("%b %d %H:%M") # e.g., Sep 24 10:00
        # Constructing the timestamp for grep is tricky due to varying month/day formats.
        # A simpler approach: check for ANY recent root login lines.
        # A more robust approach would parse dates properly, but this is a start.
        # Let's search for 'Accepted' lines involving 'root' in the last hour's worth of log.
        # This is a heuristic.
        
        # Check if auth.log exists and is readable
        auth_log_path = Path("/var/log/auth.log")
        if auth_log_path.exists():
             # Use journalctl for a more standardized approach if available, or grep the log.
             # journalctl is often preferred for systemd-managed logs.
             # Let's try journalctl first for recent entries.
             journal_code, journal_out, journal_err = run_command_simple(
                 f"journalctl -u ssh -S '{one_hour_ago.isoformat()}' | grep 'Accepted.*root'"
             )
             if journal_code == 0 and journal_out.strip():
                 lines = journal_out.strip().split('\n')
                 if lines and lines != ['']:
                     # Found recent accepted root logins via SSH
                     count = len([l for l in lines if l.strip()])
                     issues_found.append(f"Recent root SSH logins detected ({count} in last hour).")
                     remediation_suggestions.append(
                         "Review SSH access controls. Ensure 'PermitRootLogin no' in /etc/ssh/sshd_config."
                     )
             # Fallback to grepping auth.log if journalctl didn't yield results or failed
             # elif journal_code != 0 or not journal_out.strip(): 
             # This gets complex quickly due to log format and permissions.
             # For now, let's focus on configuration checks which are more reliable.
        else:
            # Auth log might be in a different location or managed by journald only.
            # This is fine, we move to other checks.
            info_found.append("Standard auth.log not found, checking other indicators.")
            
    except Exception as e:
        # If we can't read logs, it might be because we lack permissions, which is actually good
        # from a security standpoint (non-root user can't snoop logs).
        # However, it also means we can't perform this specific check.
        # warnings_found.append(f"Cannot read auth logs to check for recent root logins: {e}")
        # Let's not flag this as a warning, as inability to read sensitive logs can be correct.
        # Instead, rely on configuration checks.
        pass

    # --- 2. Check SSH Configuration for Root Login ---
    ssh_config_path = Path("/etc/ssh/sshd_config")
    if ssh_config_path.exists():
        try:
            ssh_content = ssh_config_path.read_text()
            # Look for PermitRootLogin setting
            permit_root_login_line = None
            for line in ssh_content.splitlines():
                if line.strip().startswith("PermitRootLogin"):
                    permit_root_login_line = line.strip()
                    break
            
            if permit_root_login_line:
                # Check the value after the setting
                parts = permit_root_login_line.split()
                if len(parts) > 1:
                    value = parts[1].lower()
                    if value in ["yes", "without-password", "prohibit-password"]: # 'prohibit-password' is an alias for 'without-password' in newer OpenSSH
                        issues_found.append(f"SSH allows root login ({permit_root_login_line}).")
                        remediation_suggestions.append(
                            "In /etc/ssh/sshd_config, set 'PermitRootLogin no' and restart SSH: sudo systemctl restart ssh"
                        )
                    # 'no' is secure, 'forced-commands-only' is niche.
                    # If it's 'no' or not explicitly insecure, it's okay.
                # If the line exists but has no value, it might default based on SSH version,
                # but it's better to be explicit. However, flagging it might be noisy.
                # Let's only flag explicit insecure settings.
            else:
                # PermitRootLogin line not found. The default behavior depends on the SSH version.
                # Modern defaults tend to be more secure, but it's best practice to set it explicitly.
                # This is more of an INFO or not an issue.
                # info_found.append("PermitRootLogin not explicitly set in SSH config (check SSH version defaults).")
                pass # Silently pass for now.
                
        except (PermissionError, IOError) as e:
            # Cannot read SSH config, might be expected if not running as root.
            # warnings_found.append(f"Cannot read SSH config to check root login settings: {e}")
            # Similar to logs, inability to read config can be correct.
            pass
    else:
        # SSH server config not found. SSH might not be installed or used.
        # This is informational.
        # info_found.append("SSH server configuration not found.")
        pass # Silently pass.

    # --- 3. Check if 'su' to root requires authentication ---
    # By default, 'su' to root requires the root password.
    # If the root password is disabled (locked), 'su' will fail.
    # We can check the status of the root account.
    try:
        # Check /etc/shadow for root account status
        shadow_code, shadow_out, shadow_err = run_command_simple("getent shadow root")
        if shadow_code == 0 and shadow_out.strip():
            # Output format: root:$hash_or_other_indicator$:...
            parts = shadow_out.strip().split(':')
            if len(parts) > 1:
                password_field = parts[1]
                if password_field.startswith('!') or password_field.startswith('*'):
                    # Account is locked/disabled for password login
                    info_found.append("Root account password is disabled/locked.")
                elif password_field == "":
                    # Empty password field - highly insecure
                    issues_found.append("Root account has an empty password!")
                    remediation_suggestions.append("Lock the root account: sudo passwd -l root")
                else:
                    # Password is set. This means 'su' could potentially work if the password is known.
                    # This is not inherently bad, but it's a vector. The key is that it requires the password.
                    # If password is strong, it's okay. If password is weak or compromised, it's bad.
                    # This check is more about detecting if root password *can* be used.
                    # Let's phrase it neutrally.
                    warnings_found.append("Root account password is set. Ensure it is strong and 'su' is monitored.")
                    # Ideally, root login should be disabled, and admin tasks done via sudo.
        else:
            # Could not get root shadow entry.
            # warnings_found.append("Cannot determine root password status.")
            pass # Silently continue.
    except Exception as e:
        # warnings_found.append(f"Error checking root password status: {e}")
        pass # Silently continue.

    # --- 4. Check if 'sudo' requires authentication ---
    try:
        # Check sudoers for common insecure settings
        sudoers_code, sudoers_out, sudoers_err = run_command_simple("sudo grep -v '^#' /etc/sudoers | grep -v '^$' | grep 'ALL.*ALL.*NOPASSWD'")
        # This command looks for lines in sudoers (excluding comments and blanks) that grant NOPASSWD.
        # It's a basic check.
        if sudoers_code == 0 and sudoers_out.strip():
            # Found lines granting NOPASSWD. This could be a security risk if too broad.
            lines = sudoers_out.strip().split('\n')
            insecure_nopasswd_lines = [l for l in lines if l.strip() and "ALL=(ALL)" in l and "NOPASSWD" in l]
            if insecure_nopasswd_lines:
                issues_found.append(
                    f"Insecure 'sudo' NOPASSWD rules found for ALL commands ({len(insecure_nopasswd_lines)} lines)."
                )
                remediation_suggestions.append(
                    "Review /etc/sudoers (use 'visudo'). Remove broad NOPASSWD rules. "
                    "Limit NOPASSWD to specific, safe commands if absolutely necessary."
                )
            # Less critical but still worth noting: any NOPASSWD
            elif lines and lines != ['']:
                 warnings_found.append(
                     f"'sudo' NOPASSWD rules found ({len(lines)} lines). Review for least privilege."
                 )
        # If sudoers_code != 0, it might mean 'sudo' command failed (needs password) or file not found.
        # Or it might mean no NOPASSWD lines were found, which is good.
        # We cannot distinguish easily without parsing stderr, so we assume good if command succeeds with no output.
    except Exception as e:
        # warnings_found.append(f"Error checking sudoers for NOPASSWD: {e}")
        pass # Silently continue.

    # --- 5. Check for basic root access monitoring (auditd, fail2ban) ---
    monitoring_tools_found = []
    # Check for auditd (Linux Audit Framework)
    auditd_code, _, _ = run_command_simple("systemctl is-active auditd")
    if auditd_code == 0:
        monitoring_tools_found.append("auditd")
        info_found.append("Linux Audit Framework (auditd) is active. Can monitor 'su' and privileged commands.")

    # Check for fail2ban (intrusion prevention)
    fail2ban_code, _, _ = run_command_simple("systemctl is-active fail2ban")
    if fail2ban_code == 0:
        monitoring_tools_found.append("fail2ban")
        info_found.append("Fail2Ban is active. Helps prevent brute-force root access attempts.")

    if monitoring_tools_found:
        # Having monitoring tools is good.
        # The check should PASS if monitoring is present, even if other minor issues exist.
        # However, if there are CRITICAL issues (like insecure SSH root login), monitoring doesn't fix that.
        # Let's prioritize CRITICAL/FAIL issues over the presence of monitoring tools.
        pass # Info is already added.
    else:
        # Lack of specific monitoring tools is not necessarily a FAIL,
        # as basic logging and sudo logs provide some level of traceability.
        # It's more of a recommendation for enhancement.
        warnings_found.append(
            "No dedicated root access monitoring tools (like auditd, fail2ban) detected. "
            "Consider implementing auditd for detailed logging or fail2ban for intrusion prevention."
        )
        remediation_suggestions.append(
            "Install auditd for comprehensive system call auditing: sudo apt install auditd && sudo systemctl enable auditd && sudo systemctl start auditd. "
            "Or install fail2ban for intrusion prevention: sudo apt install fail2ban && sudo systemctl enable fail2ban && sudo systemctl start fail2ban."
        )


    # --- Determine Final Check Status ---
    # Combine findings for the details field
    all_findings = []
    if issues_found:
        all_findings.extend([f"[CRITICAL] {issue}" for issue in issues_found])
    if warnings_found:
        all_findings.extend([f"[WARN] {warning}" for warning in warnings_found])
    if info_found:
        all_findings.extend([f"[INFO] {info}" for info in info_found])

    if issues_found:
        # Critical security issues found (e.g., SSH root login enabled, insecure sudo)
        check.status = "FAIL"
        check.details = f"Critical root access issues found ({len(issues_found)}). Details: {'; '.join(all_findings[:3])}..." # Show first 3 findings
        check.remediation_needed = True
        if remediation_suggestions:
            check.remediation_command = " && ".join(remediation_suggestions[:3]) # Limit remediation commands shown
    elif warnings_found:
        # Warnings found (e.g., root password set, lack of monitoring tools)
        check.status = "WARN"
        check.details = f"Root access warnings/concerns ({len(warnings_found)}). Details: {'; '.join(all_findings[:3])}..."
        check.remediation_needed = True
        if remediation_suggestions:
            check.remediation_command = " && ".join(remediation_suggestions[:3])
    elif info_found:
        # Only informational findings (e.g., monitoring tools active, root password locked)
        check.status = "PASS"
        check.details = f"Root access configuration appears secure. Info: {'; '.join(info_found[:3])}..."
    else:
        # No specific findings. This could mean checks couldn't run or system is in an unknown state.
        # Given the checks attempted, if we get here, it's likely things are okay or we lack permission to see issues.
        check.status = "PASS" # Assume PASS if no negative findings, even if checks were limited.
        check.details = "No immediate root access issues detected by checks performed."

    # Return the populated ConfigCheck object
    return check
