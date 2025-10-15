# privaware_pkg/core/checks/check_integrity_monitoring.py
"""
Advanced Check for Integrity Monitoring Presence and Configuration.
This check verifies if file integrity monitoring tools (AIDE, Tripwire, Samhain, etc.) 
are not only installed but also actively configured and running.
"""

# Import the necessary classes and helpers from the common models file
import os
from pathlib import Path
from ..config_models import ConfigCheck, run_command_simple

def check_integrity_monitoring() -> ConfigCheck:
    """
    Advanced check for integrity monitoring presence and active configuration.

    This check goes beyond just detecting if FIM tools are installed. It attempts to:
    1. Detect installed FIM tools (AIDE, Tripwire, Samhain, etc.).
    2. Check if configuration files exist.
    3. Verify if databases/signatures are initialized.
    4. Check if services/daemons are running.
    5. Assess the basic health/status of the FIM system.

    Returns:
        ConfigCheck: Result of the check including status (PASS/WARN/FAIL/UNKNOWN),
                     detailed information about the FIM system's state, and remediation info.
    """
    # Create the check object instance
    check = ConfigCheck("integrity_monitoring", "Integrity monitoring presence & status", "MEDIUM")

    # --- Enhanced Logic for Comprehensive FIM Assessment ---

    detected_fim_tool = None
    fim_details = []
    is_configured = False
    is_active = False
    remediation_steps = []

    # --- 1. Check for AIDE (Advanced Intrusion Detection Environment) ---
    aide_code, aide_out, aide_err = run_command_simple("which aide")
    if aide_code == 0 and aide_out.strip():
        detected_fim_tool = "AIDE"
        fim_details.append("AIDE binary found.")

        # Check for configuration file
        aide_configs = ["/etc/aide/aide.conf", "/etc/aide.conf"]
        aide_config_found = False
        for config_path in aide_configs:
            if os.path.exists(config_path):
                aide_config_found = True
                fim_details.append(f"AIDE config found at {config_path}.")
                break
        
        if not aide_config_found:
            fim_details.append("AIDE binary found but no configuration file detected.")
            remediation_steps.append("Create AIDE configuration: sudo cp /etc/aide/aide.conf.default /etc/aide/aide.conf")

        # Check for initialized database
        aide_db_paths = ["/var/lib/aide/aide.db.gz", "/var/lib/aide/aide.db"]
        aide_db_found = any(os.path.exists(p) for p in aide_db_paths)
        if aide_db_found:
            fim_details.append("AIDE database initialized.")
            is_configured = True # Basic configuration implies readiness
        else:
            fim_details.append("AIDE binary and config found but database not initialized.")
            # Check if init command can be run non-interactively (might require sudo)
            # This is a heuristic; actual init requires user interaction or specific flags.
            remediation_steps.append("Initialize AIDE database: sudo aide --init")

        # Check if AIDE service is running (less common, but possible)
        aide_svc_code, _, _ = run_command_simple("systemctl is-active aide")
        if aide_svc_code == 0:
            fim_details.append("AIDE service is active.")
            is_active = True
        else:
            # AIDE is typically run via cron, not a persistent daemon
            fim_details.append("AIDE service not found or not active (common for AIDE).")

    # --- 2. Check for Tripwire ---
    if not detected_fim_tool:
        tripwire_code, tripwire_out, tripwire_err = run_command_simple("which tripwire")
        if tripwire_code == 0 and tripwire_out.strip():
            detected_fim_tool = "Tripwire"
            fim_details.append("Tripwire binary found.")

            # Check for Tripwire configuration files
            tripwire_cfg_dir = "/etc/tripwire"
            if os.path.exists(tripwire_cfg_dir) and os.path.isdir(tripwire_cfg_dir):
                cfg_files = os.listdir(tripwire_cfg_dir)
                if cfg_files:
                    fim_details.append(f"Tripwire config directory ({tripwire_cfg_dir}) exists with files.")
                    is_configured = True # Presence of config dir/files is a good sign
                else:
                    fim_details.append(f"Tripwire config directory ({tripwire_cfg_dir}) is empty.")
                    remediation_steps.append("Configure Tripwire: Refer to Tripwire documentation for setup.")
            else:
                fim_details.append("Tripwire binary found but config directory missing.")
                remediation_steps.append("Create Tripwire config: Refer to Tripwire documentation.")

            # Check for initialized databases (policy and DB files)
            tw_db_dir = "/var/lib/tripwire"
            if os.path.exists(tw_db_dir) and os.listdir(tw_db_dir):
                fim_details.append("Tripwire databases directory exists.")
                # Further checks for specific .twd files could be done here.
            else:
                fim_details.append("Tripwire databases not initialized or directory missing.")
                remediation_steps.append("Initialize Tripwire databases: Refer to Tripwire documentation.")

            # Check if Tripwire service is running (less common for basic setups)
            tw_svc_code, _, _ = run_command_simple("systemctl is-active tripwire")
            if tw_svc_code == 0:
                fim_details.append("Tripwire service is active.")
                is_active = True
            else:
                fim_details.append("Tripwire service not found or not active (common for scheduled checks).")

    # --- 3. Check for Samhain ---
    if not detected_fim_tool:
        samhain_code, samhain_out, samhain_err = run_command_simple("which samhain")
        if samhain_code == 0 and samhain_out.strip():
            detected_fim_tool = "Samhain"
            fim_details.append("Samhain binary found.")

            # Check for Samhain configuration file
            samhain_configs = ["/etc/samhain/samhainrc", "/etc/samhainrc"]
            samhain_config_found = False
            for config_path in samhain_configs:
                if os.path.exists(config_path):
                    samhain_config_found = True
                    fim_details.append(f"Samhain config found at {config_path}.")
                    is_configured = True
                    break
            
            if not samhain_config_found:
                fim_details.append("Samhain binary found but no configuration file detected.")
                remediation_steps.append("Create Samhain configuration.")

            # Check if Samhain daemon is running
            samhain_svc_code, _, _ = run_command_simple("systemctl is-active samhain")
            if samhain_svc_code == 0:
                fim_details.append("Samhain daemon is active.")
                is_active = True
            else:
                # Check using `ps` as a fallback
                ps_code, ps_out, _ = run_command_simple("ps aux | grep '[s]amhain' | grep -v grep")
                if ps_code == 0 and ps_out:
                    fim_details.append("Samhain process is running.")
                    is_active = True
                else:
                    fim_details.append("Samhain binary found but daemon is not running.")
                    remediation_steps.append("Start Samhain daemon: sudo systemctl start samhain")

    # --- 4. Check for systemd-based integrity checking units (generic) ---
    if not detected_fim_tool:
        # This is a broader check for any systemd service/unit related to integrity
        systemd_code, systemd_out, _ = run_command_simple("systemctl list-unit-files --type=service | grep -i 'integrity'")
        if systemd_code == 0 and systemd_out.strip():
            # Found systemd services with 'integrity' in the name
            detected_fim_tool = "Systemd Integrity Service"
            lines = systemd_out.strip().split('\n')
            service_names = [line.split()[0] for line in lines if line.strip()]
            fim_details.append(f"Potential systemd integrity services detected: {', '.join(service_names[:3])}...")
            
            # Check if any of these services are active
            for service in service_names:
                svc_status_code, _, _ = run_command_simple(f"systemctl is-active {service}")
                if svc_status_code == 0:
                    fim_details.append(f"Systemd service '{service}' is active.")
                    is_configured = True # If a service exists and is active, it's configured
                    is_active = True
                    break # Assume one active is sufficient for a basic PASS
            if not is_active:
                fim_details.append("Systemd integrity services found but none are currently active.")
                # Determining how to start/configure a generic unknown service is difficult.
                # Remediation would be specific to the service found.
                remediation_steps.append("Investigate and start the specific integrity service.")

    # --- 5. Check for basic rootkit detection tools (Warnings) ---
    if not detected_fim_tool:
        rootkit_tools = [("chkrootkit", "chkrootkit"), ("rkhunter", "rkhunter")]
        for tool_display_name, tool_command in rootkit_tools:
            tool_code, tool_out, _ = run_command_simple(f"which {tool_command}")
            if tool_code == 0 and tool_out.strip():
                detected_fim_tool = f"{tool_display_name} (Basic Detection)"
                check.status = "WARN"
                check.details = (
                    f"{tool_display_name} rootkit/basic detection tool found. "
                    "Provides periodic scans but not continuous file integrity monitoring."
                )
                check.remediation_needed = True
                check.remediation_command = (
                    f"{tool_display_name} offers basic security scanning. "
                    "Consider installing a dedicated FIM tool like AIDE or Tripwire for real-time monitoring: "
                    "sudo apt install aide && sudo aide --init"
                )
                return check # Return early with a warning

    # --- Determine Final Check Status ---
    if detected_fim_tool:
        # A FIM tool was detected
        if is_active:
            # Best case: Tool is installed, configured, and actively running
            check.status = "PASS"
            check.details = f"{detected_fim_tool} is installed, configured, and actively monitoring."
        elif is_configured:
            # Good: Tool is installed and has basic configuration/database
            check.status = "WARN"
            check.details = f"{detected_fim_tool} is installed and configured but may not be actively running."
            check.remediation_needed = True
            remediation_steps.append(f"Ensure {detected_fim_tool} is scheduled (e.g., via cron) or its service is started.")
        else:
            # Tool found, but lacks configuration or database
            check.status = "FAIL"
            check.details = f"{detected_fim_tool} binary found but not properly configured or initialized."
            check.remediation_needed = True
        # Append detailed findings
        if fim_details:
            check.details += f" Details: {'; '.join(fim_details)}"
        # Provide specific remediation steps if needed
        if remediation_steps:
            check.remediation_command = " && ".join(remediation_steps)
    else:
        # No FIM tool detected at all
        check.status = "FAIL"
        check.details = (
            "No recognized integrity monitoring system (AIDE, Tripwire, Samhain) or "
            "systemd integrity service detected. System lacks continuous file integrity monitoring."
        )
        check.remediation_needed = True
        # Provide a concrete remediation command for a common FIM tool
        check.remediation_command = (
            "Install AIDE for file integrity monitoring: "
            "sudo apt update && sudo apt install aide && "
            "sudo cp /etc/aide/aide.conf.d/* /etc/aide/aide.conf 2>/dev/null || "
            "sudo cp /etc/aide.conf.default /etc/aide/aide.conf 2>/dev/null || "
            "echo '# Basic AIDE config' | sudo tee /etc/aide/aide.conf && "
            "sudo aide --init"
        )

    # Return the final, populated ConfigCheck object
    return check
