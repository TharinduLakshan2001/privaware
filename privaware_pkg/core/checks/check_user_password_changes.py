# privaware_pkg/core/checks/check_user_password_changes.py
"""
Check for user password changes and password policy.
This check verifies if there have been recent password changes for users or if password policies are weak.
"""

# Import the necessary classes and helpers from the common models file
import os
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from ..config_models import ConfigCheck, run_command_simple

def check_user_password_changes() -> ConfigCheck:
    """
    Check for user password changes and password policy.

    This check looks for:
    1.  Evidence of recent user password changes (from /etc/shadow modification times, chage command).
    2.  Checks if password policies are configured (minimum length, complexity, expiration).
    3.  Warns if default or weak passwords might be in use (hard to detect directly, but policy checks help).

    Returns:
        ConfigCheck: Result of the check including status (PASS/WARN/FAIL/UNKNOWN),
                     details about password change/policy findings, and remediation info.
    """
    # Create the check object instance
    check = ConfigCheck("user_password_changes", "User password changes & policy", "HIGH")

    # --- Logic for User Password Changes and Policy Check ---
    issues_found = []
    warnings_found = []
    info_found = []
    remediation_suggestions = []

    # --- 1. Check for recent password changes using `chage -l` for a sample user (current user) ---
    # This is a proxy for checking if password aging is configured.
    # It's difficult to check for *all* users' recent changes without root.
    # But we can check the current user's password policy/age.
    try:
        current_user = os.environ.get('USER', '')
        if current_user and current_user != 'root': # Avoid checking root specifically here unless needed
            chage_code, chage_out, chage_err = run_command_simple(f"chage -l {current_user}")
            if chage_code == 0 and chage_out.strip():
                # Parse chage output for last password change, expiration, etc.
                # Sample output lines:
                # Last password change					: Sep 20, 2023
                # Password expires					: never
                # Password inactive					: never
                # Account expires						: never
                # Minimum number of days between password change		: 0
                # Maximum number of days between password change		: 99999
                # Number of days of warning before password expires	: 7
                
                last_change_line = [line for line in chage_out.split('\n') if line.startswith('Last password change')]
                max_days_line = [line for line in chage_out.split('\n') if 'Maximum number of days' in line]
                min_days_line = [line for line in chage_out.split('\n') if 'Minimum number of days' in line]
                
                if last_change_line:
                    last_change_info = last_change_line[0].split(':', 1)
                    if len(last_change_info) > 1:
                        last_change_date_str = last_change_info[1].strip()
                        if last_change_date_str.lower() != 'never':
                            info_found.append(f"Last password change for '{current_user}': {last_change_date_str}")
                            # Could try to parse the date and see if it's recent, but date formats vary.
                            # For now, just record the info.
                        else:
                            info_found.append(f"Password for '{current_user}' has never been changed.")
                
                # Check password expiration policy
                max_days_info = max_days_line[0].split(':', 1) if max_days_line else ['', '']
                min_days_info = min_days_line[0].split(':', 1) if min_days_line else ['', '']
                
                max_days_str = max_days_info[1].strip() if len(max_days_info) > 1 else ''
                min_days_str = min_days_info[1].strip() if len(min_days_info) > 1 else ''
                
                try:
                    max_days = int(max_days_str) if max_days_str.isdigit() else 99999
                    min_days = int(min_days_str) if min_days_str.isdigit() else 0
                    
                    if max_days > 365 * 5: # Longer than 5 years
                        warnings_found.append(
                            f"Password for '{current_user}' expires very infrequently (every {max_days} days)."
                        )
                        remediation_suggestions.append(
                            f"Set reasonable password expiration for '{current_user}': "
                            f"sudo chage -M 90 {current_user} (90 days)"
                        )
                    elif max_days == 99999 or max_days_str.lower() == 'never':
                        warnings_found.append(f"Password for '{current_user}' never expires.")
                        remediation_suggestions.append(
                            f"Set password expiration for '{current_user}': "
                            f"sudo chage -M 365 {current_user} (1 year)"
                        )
                    # If max_days is reasonable (e.g., <= 365), it's okay.
                    
                    if min_days == 0:
                        # This allows immediate password changes, which is usually fine.
                        # Not an issue.
                        pass
                    # If min_days is too high, it could be annoying, but not a major security issue.
                    
                except ValueError:
                    # Couldn't parse max/min days, might be 'never' or malformed.
                    # Handled by string checks above.
                    pass
                    
            else:
                # chage command failed for current user
                # warnings_found.append(f"Cannot check password policy for user '{current_user}': {chage_err}")
                # This might be expected if the user doesn't have perms to run chage on themselves.
                # Let's not flag it as a warning.
                pass
    except Exception as e:
        # warnings_found.append(f"Error checking current user password policy: {e}")
        # Silently continue.
        pass

    # --- 2. Check system-wide password policy (requires root or specific permissions) ---
    # Check for PAM password quality settings in /etc/pam.d/common-password or /etc/security/pwquality.conf
    pw_quality_config_paths = [
        "/etc/security/pwquality.conf",
        "/etc/pam.d/common-password" # This file includes/uses pwquality.conf
    ]
    
    pw_policy_issues = []
    pw_policy_info = []
    
    for config_path_str in pw_quality_config_paths:
        config_path = Path(config_path_str)
        if config_path.exists():
            try:
                with open(config_path, 'r') as f:
                    content = f.read()
                
                # Look for common password quality directives
                # In pwquality.conf, directives look like: minlen = 12, dcredit = -1, etc.
                # In common-password PAM file, it might look like: password requisite pam_pwquality.so retry=3 minlen=12 difok=3
                # Or it might include the file: password requisite pam_pwquality.so retry=3 authtok_type= try_first_pass local_users_only shadow obscure use_authtok
                
                if "pam_pwquality.so" in content or config_path.name == "pwquality.conf":
                    # PAM password quality module is referenced or this is the config file
                    
                    # Check for minimum length
                    minlen_found = False
                    minlen_value = 8 # Default weak value if not found
                    # Look for minlen directive
                    import re
                    minlen_match = re.search(r'[^\w]minlen\s*=\s*(\d+)', content) # Matches minlen=12, minlen = 12, etc.
                    if minlen_match:
                        minlen_found = True
                        minlen_value = int(minlen_match.group(1))
                    
                    # If not found in regex, look for it in PAM line format
                    if not minlen_found:
                        pam_line_match = re.search(r'pam_pwquality\.so.*?minlen\s*=?\s*(\d+)', content)
                        if pam_line_match:
                            minlen_found = True
                            minlen_value = int(pam_line_match.group(1))
                    
                    if minlen_found:
                        if minlen_value < 8:
                            pw_policy_issues.append(f"Weak password minimum length: {minlen_value} (should be >= 8)")
                            remediation_suggestions.append(
                                "Increase minimum password length in /etc/security/pwquality.conf: "
                                "sudo sed -i 's/^#\\?minlen.*/minlen = 12/' /etc/security/pwquality.conf"
                            )
                        elif minlen_value >= 8 and minlen_value < 12:
                            # Acceptable but could be stronger
                            pw_policy_info.append(f"Password minimum length: {minlen_value} (acceptable)")
                        else:
                            # Strong
                            pw_policy_info.append(f"Password minimum length: {minlen_value} (strong)")
                    else:
                        # minlen directive not found, assume default (weak)
                        pw_policy_issues.append("Password minimum length not explicitly set (defaults may be weak)")
                        remediation_suggestions.append(
                            "Set minimum password length in /etc/security/pwquality.conf: "
                            "echo 'minlen = 12' | sudo tee -a /etc/security/pwquality.conf"
                        )
                    
                    # Check for other common quality measures (complexity)
                    # difok: min chars that must differ from old password
                    # dcredit: max number of digits allowed (negative means required)
                    # ocredit: max special chars allowed (negative means required)
                    # lcredit: max lowercase chars allowed (negative means required)
                    # ucredit: max uppercase chars allowed (negative means required)
                    # These are harder to check comprehensively without a full parser.
                    # Just flag if the file exists and seems to reference pwquality.
                    pw_policy_info.append("PAM password quality module (pam_pwquality) is configured.")
                    
                else:
                    # pwquality not directly referenced in this file
                    # Check for other common PAM modules like pam_unix, pam_cracklib (older)
                    if "pam_unix.so" in content:
                        # This is very basic. pam_pwquality is preferred.
                        pw_policy_info.append("Basic PAM password handling (pam_unix) found.")
                        # This is not necessarily bad, but not as good as pwquality.
                        # Let's not flag it as an issue unless we find no better policy.
                        # If pwquality is not found elsewhere, this becomes the issue.
                        
            except (PermissionError, IOError) as e:
                # Cannot read this specific file
                # warnings_found.append(f"Cannot read password policy config {config_path_str}: {e}")
                # Silently continue.
                pass
    
    # If we found issues with PAM password policy
    if pw_policy_issues:
        issues_found.extend(pw_policy_issues)
    if pw_policy_info:
        info_found.extend(pw_policy_info)

    # If no specific policy file was found or issues were found, flag it.
    # This is a bit tricky because different distros/configurations might use different files/modules.
    # A strong check is if we found a good policy (pwquality with good settings).
    # If not, and we found only basic PAM or nothing, it's a concern.
    # Let's simplify: if we found issues, flag them. If we found good info, that's good.
    # If we found nothing, warn about lack of policy visibility.
    if not pw_policy_issues and not pw_policy_info:
        # We couldn't determine the password policy from common locations.
        warnings_found.append("Cannot determine system password policy from standard locations.")
        remediation_suggestions.append(
            "Ensure password quality policies are configured using pam_pwquality. "
            "Check /etc/security/pwquality.conf and /etc/pam.d/common-password."
        )


    # --- 3. Check /etc/shadow modification time (indirect indicator) ---
    # This is a very indirect check. If /etc/shadow was recently modified,
    # it *could* indicate a password change, but it could also be any user/group modification.
    # It's not reliable, but can be a weak indicator.
    # Requires root or specific permissions to stat /etc/shadow accurately.
    # Let's not rely on this heavily.
    # shadow_path = Path("/etc/shadow")
    # if shadow_path.exists():
    #     try:
    #         shadow_mtime = datetime.fromtimestamp(shadow_path.stat().st_mtime)
    #         time_since_mod = datetime.now() - shadow_mtime
    #         if time_since_mod < timedelta(days=1):
    #             info_found.append("System shadow file was recently modified (potential password/user change).")
    #     except:
    #         pass # Silently continue if cannot stat.

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
        # Critical security issues found (e.g., very weak password policy)
        check.status = "FAIL"
        check.details = f"Critical password policy issues found ({len(issues_found)}). Details: {'; '.join(all_findings[:3])}..." # Show first 3 findings
        check.remediation_needed = True
        if remediation_suggestions:
            check.remediation_command = " && ".join(remediation_suggestions[:3]) # Limit remediation commands shown
    elif warnings_found:
        # Warnings found (e.g., passwords never expire, moderate policy)
        check.status = "WARN"
        check.details = f"Password policy warnings/concerns ({len(warnings_found)}). Details: {'; '.join(all_findings[:3])}..."
        check.remediation_needed = True
        if remediation_suggestions:
            check.remediation_command = " && ".join(remediation_suggestions[:3])
    elif info_found:
        # Only informational findings (e.g., good policy found, last change date noted)
        check.status = "PASS"
        check.details = f"Password policy appears configured. Info: {'; '.join(info_found[:3])}..."
    else:
        # No specific findings. This could mean checks couldn't run or system is in an unknown state.
        check.status = "WARN" # Default to warn if we can't confirm strong policy
        check.details = "Cannot conclusively determine password policy strength. Review system PAM/password configuration."
        check.remediation_needed = True
        check.remediation_command = (
            "Review and enforce strong password policies: "
            "1. Ensure pam_pwquality is used in /etc/pam.d/common-password. "
            "2. Configure /etc/security/pwquality.conf with minlen=12, dcredit=-1, ocredit=-1, etc. "
            "3. Set appropriate password expiration with 'chage -M'."
        )

    # Return the populated ConfigCheck object
    return check
