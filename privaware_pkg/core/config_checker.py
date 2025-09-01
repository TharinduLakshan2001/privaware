"""
Config Checker: Privacy configuration monitoring and auditing.
"""
import os
import json
import yaml
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any
import hashlib

class ConfigCheck:
    def __init__(self, check_id: str, description: str, severity: str = "MEDIUM"):
        self.check_id = check_id
        self.description = description
        self.severity = severity
        self.status = "UNKNOWN"  # PASS, WARN, FAIL, UNKNOWN
        self.details = ""
        self.remediation_needed = False
        self.remediation_attempted = False
        self.remediation_result = ""

    def to_dict(self):
        return {
            'check_id': self.check_id,
            'description': self.description,
            'status': self.status,
            'severity': self.severity,
            'details': self.details,
            'remediation_needed': self.remediation_needed,
            'remediation_attempted': self.remediation_attempted,
            'remediation_result': self.remediation_result,
            'timestamp': datetime.now().isoformat()
        }

class ConfigChecker:
    def __init__(self, snapshot_dir="~/.privaware/snapshots", profile="balanced"):
        self.snapshot_dir = Path(os.path.expanduser(snapshot_dir))
        self.profile = profile
        self.snapshot_dir.mkdir(parents=True, exist_ok=True)
        self.checks = self._initialize_checks()
    
    def _initialize_checks(self) -> List[ConfigCheck]:
        """Initialize all privacy checks"""
        checks = [
            ConfigCheck("firewall_active", "Firewall active & default policy", "HIGH"),
            ConfigCheck("dns_resolver", "DNS resolver configuration", "MEDIUM"),
            ConfigCheck("vpn_status", "VPN interface & killswitch", "HIGH"),
            ConfigCheck("exposed_services", "Exposed listening services", "HIGH"),
            ConfigCheck("ssh_hardening", "SSH hardening settings", "HIGH"),
            ConfigCheck("disk_encryption", "Full-disk encryption", "CRITICAL"),
            ConfigCheck("swap_encryption", "Swap encryption", "HIGH"),
            ConfigCheck("mac_randomization", "Wi-Fi MAC randomization", "MEDIUM"),
            ConfigCheck("auto_mount", "Auto-mount disabled", "MEDIUM"),
            ConfigCheck("selinux_status", "SELinux/AppArmor status", "MEDIUM"),
            ConfigCheck("shell_history", "Shell history protections", "LOW"),
            ConfigCheck("log_permissions", "Log permissions and rotation", "MEDIUM"),
            ConfigCheck("unauthorized_cron", "Unauthorized cron/systemd timers", "HIGH"),
            ConfigCheck("system_updates", "System updates available", "MEDIUM"),
            ConfigCheck("integrity_monitoring", "Integrity monitoring presence", "MEDIUM")
        ]
        return checks
    
    def _run_command(self, command: str, shell=False) -> tuple:
        """Run system command and return output"""
        try:
            if shell:
                result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=10)
            else:
                result = subprocess.run(command.split(), capture_output=True, text=True, timeout=10)
            return result.returncode, result.stdout.strip(), result.stderr.strip()
        except subprocess.TimeoutExpired:
            return -1, "", "Command timed out"
        except Exception as e:
            return -1, "", str(e)
    
    def check_firewall(self) -> ConfigCheck:
        """Check firewall status"""
        check = ConfigCheck("firewall_active", "Firewall active & default policy", "HIGH")
        
        # Check ufw
        code, out, err = self._run_command("ufw status")
        if code == 0 and "Status: active" in out:
            check.status = "PASS"
            check.details = "UFW firewall is active"
            return check
        
        # Check iptables
        code, out, err = self._run_command("iptables -L")
        if code == 0 and out:
            check.status = "WARN"
            check.details = "iptables rules present but status unclear"
            return check
        
        # Check nftables
        code, out, err = self._run_command("nft list rulesets")
        if code == 0 and out:
            check.status = "WARN"
            check.details = "nftables rules present but status unclear"
            return check
        
        check.status = "FAIL"
        check.details = "No active firewall detected"
        check.remediation_needed = True
        return check
    
    def check_dns_resolver(self) -> ConfigCheck:
        """Check DNS resolver configuration"""
        check = ConfigCheck("dns_resolver", "DNS resolver configuration", "MEDIUM")
        
        # Check resolv.conf
        try:
            with open("/etc/resolv.conf", "r") as f:
                content = f.read()
                if "nameserver" in content:
                    check.status = "PASS"
                    check.details = f"DNS configured: {content[:100]}..."
                else:
                    check.status = "FAIL"
                    check.details = "No DNS nameservers configured"
                    check.remediation_needed = True
        except Exception as e:
            check.status = "UNKNOWN"
            check.details = f"Cannot read resolv.conf: {e}"
        
        return check
    
    def check_ssh_hardening(self) -> ConfigCheck:
        """Check SSH hardening settings"""
        check = ConfigCheck("ssh_hardening", "SSH hardening settings", "HIGH")
        
        try:
            # Check SSH config
            ssh_config_path = "/etc/ssh/sshd_config"
            if os.path.exists(ssh_config_path):
                with open(ssh_config_path, "r") as f:
                    content = f.read()
                    
                issues = []
                if "PermitRootLogin yes" in content or "#PermitRootLogin" in content:
                    issues.append("Root login allowed")
                
                if "PasswordAuthentication yes" in content or "#PasswordAuthentication" in content:
                    issues.append("Password authentication enabled")
                
                if issues:
                    check.status = "FAIL"
                    check.details = "; ".join(issues)
                    check.remediation_needed = True
                else:
                    check.status = "PASS"
                    check.details = "SSH hardening settings OK"
            else:
                check.status = "UNKNOWN"
                check.details = "SSH config file not found"
        except Exception as e:
            check.status = "UNKNOWN"
            check.details = f"Cannot read SSH config: {e}"
        
        return check
    
    def check_disk_encryption(self) -> ConfigCheck:
        """Check full-disk encryption"""
        check = ConfigCheck("disk_encryption", "Full-disk encryption", "CRITICAL")
        
        # Check for encrypted root filesystem
        code, out, err = self._run_command("lsblk -f")
        if code == 0:
            if "crypto_LUKS" in out or "crypt" in out:
                check.status = "PASS"
                check.details = "Encrypted filesystems detected"
            else:
                check.status = "FAIL"
                check.details = "No encrypted filesystems found"
                check.remediation_needed = True
        else:
            check.status = "UNKNOWN"
            check.details = f"Cannot check filesystems: {err}"
        
        return check

    def check_vpn_status(self) -> ConfigCheck:
        """Check VPN interface & killswitch"""
        check = ConfigCheck("vpn_status", "VPN interface & killswitch", "HIGH")
        
        # Check for VPN interfaces
        code, out, err = self._run_command("ip link show")
        if code == 0:
            vpn_indicators = ['tun', 'vpn', 'wg']
            if any(vpn in out.lower() for vpn in vpn_indicators):
                check.status = "PASS"
                check.details = "VPN interface detected"
            else:
                check.status = "WARN"
                check.details = "No active VPN interface found"
                check.remediation_needed = True
        else:
            check.status = "UNKNOWN"
            check.details = f"Cannot check interfaces: {err}"
        
        return check

    def check_exposed_services(self) -> ConfigCheck:
        """Check exposed listening services on public interfaces"""
        check = ConfigCheck("exposed_services", "Exposed listening services", "HIGH")
        
        # Check for services listening on all interfaces
        code, out, err = self._run_command("ss -tuln")
        if code == 0:
            exposed_services = []
            for line in out.split('\n'):
                if '0.0.0.0:' in line or ':::' in line:
                    exposed_services.append(line.strip())
            
            if exposed_services:
                check.status = "WARN"
                check.details = f"Services exposed on all interfaces: {len(exposed_services)} found"
                check.remediation_needed = True
            else:
                check.status = "PASS"
                check.details = "No services exposed on all interfaces"
        else:
            check.status = "UNKNOWN"
            check.details = f"Cannot check services: {err}"
        
        return check

    def check_swap_encryption(self) -> ConfigCheck:
        """Check swap encryption or encrypted swapfile"""
        check = ConfigCheck("swap_encryption", "Swap encryption", "HIGH")
        
        # Check if swap is encrypted
        code, out, err = self._run_command("swapon --show")
        if code == 0 and out:
            if 'crypto' in out.lower() or 'crypt' in out.lower():
                check.status = "PASS"
                check.details = "Encrypted swap detected"
            else:
                check.status = "FAIL"
                check.details = "Swap not encrypted"
                check.remediation_needed = True
        else:
            check.status = "UNKNOWN"
            check.details = "No swap configured or cannot check"
        
        return check

    def check_mac_randomization(self) -> ConfigCheck:
        """Check MAC randomization for Wi-Fi"""
        check = ConfigCheck("mac_randomization", "Wi-Fi MAC randomization", "MEDIUM")
        
        # Check NetworkManager config
        nm_config_paths = [
            "/etc/NetworkManager/NetworkManager.conf",
            "/etc/NetworkManager/conf.d/randomize-mac.conf"
        ]
        
        mac_randomization_found = False
        for config_path in nm_config_paths:
            if os.path.exists(config_path):
                try:
                    with open(config_path, 'r') as f:
                        content = f.read()
                        if 'wifi.scan-rand-mac-address=yes' in content or 'cloned-mac-address=random' in content:
                            mac_randomization_found = True
                            break
                except:
                    continue
        
        if mac_randomization_found:
            check.status = "PASS"
            check.details = "MAC randomization enabled"
        else:
            check.status = "WARN"
            check.details = "MAC randomization not configured"
            check.remediation_needed = True
        
        return check

    def check_auto_mount(self) -> ConfigCheck:
        """Check auto-mount/automount disabled for removable media"""
        check = ConfigCheck("auto_mount", "Auto-mount disabled", "MEDIUM")
        
        # Check various auto-mount settings
        checks = [
            ("gsettings get org.gnome.desktop.media-handling automount", "false"),
            ("gsettings get org.gnome.desktop.media-handling automount-open", "false")
        ]
        
        auto_mount_enabled = False
        for cmd, expected in checks:
            try:
                code, out, err = self._run_command(cmd)
                if code == 0 and expected not in out:
                    auto_mount_enabled = True
                    break
            except:
                continue
        
        if auto_mount_enabled:
            check.status = "WARN"
            check.details = "Auto-mount enabled for removable media"
            check.remediation_needed = True
        else:
            check.status = "PASS"
            check.details = "Auto-mount disabled"
        
        return check

    def check_selinux_status(self) -> ConfigCheck:
        """Check AppArmor/SELinux status"""
        check = ConfigCheck("selinux_status", "SELinux/AppArmor status", "MEDIUM")
        
        # Check AppArmor first
        code, out, err = self._run_command("aa-status --enabled")
        if code == 0:
            check.status = "PASS"
            check.details = "AppArmor is active"
            return check
        
        # Check SELinux
        code, out, err = self._run_command("sestatus")
        if code == 0 and "enabled" in out:
            check.status = "PASS"
            check.details = "SELinux is active"
            return check
        
        check.status = "WARN"
        check.details = "No mandatory access control system active"
        check.remediation_needed = True
        return check

    def check_shell_history(self) -> ConfigCheck:
        """Check shell history protections"""
        check = ConfigCheck("shell_history", "Shell history protections", "LOW")
        
        # Check HISTSIZE and history file permissions
        hist_size = os.environ.get('HISTSIZE', '')
        hist_file = os.environ.get('HISTFILE', '')
        
        issues = []
        if hist_size and hist_size != '0':
            issues.append(f"HISTSIZE={hist_size} (should be 0 for privacy)")
        
        if hist_file:
            try:
                hist_stat = os.stat(hist_file)
                if hist_stat.st_mode & 0o777 != 0o600:
                    issues.append(f"History file permissions: {oct(hist_stat.st_mode & 0o777)}")
            except:
                pass
        
        if issues:
            check.status = "WARN"
            check.details = "; ".join(issues)
            check.remediation_needed = True
        else:
            check.status = "PASS"
            check.details = "Shell history properly configured"
        
        return check

    def check_log_permissions(self) -> ConfigCheck:
        """Check log permissions and rotation"""
        check = ConfigCheck("log_permissions", "Log permissions and rotation", "MEDIUM")
        
        # Check common log directories
        log_dirs = ["/var/log", "/var/log/auth.log", "/var/log/syslog"]
        issues = []
        
        for log_path in log_dirs:
            if os.path.exists(log_path):
                try:
                    stat = os.stat(log_path)
                    # Check if world-readable
                    if stat.st_mode & 0o004:
                        issues.append(f"{log_path} is world-readable")
                except:
                    continue
        
        if issues:
            check.status = "WARN"
            check.details = "; ".join(issues)
            check.remediation_needed = True
        else:
            check.status = "PASS"
            check.details = "Log permissions OK"
        
        return check

    def check_unauthorized_cron(self) -> ConfigCheck:
        """Check for unauthorized cron/systemd timers (suspicious persistent tasks)"""
        check = ConfigCheck("unauthorized_cron", "Unauthorized cron/systemd timers", "HIGH")
        
        suspicious_indicators = [
            'nc', 'netcat', 'ncat',           # Network tools
            'wget', 'curl',                   # Download tools
            'bash', 'sh', 'python', 'perl',   # Scripting languages
            'reverse', 'backdoor', 'trojan',  # Obvious malicious terms
            'ssh', 'scp',                     # Remote access
            'base64', 'decode',               # Encoding/decoding
        ]
        
        issues = []
        
        try:
            # Check user crontabs
            code, out, err = self._run_command("cat /etc/passwd | cut -d: -f1")
            if code == 0:
                users = out.split('\n')
                for user in users:
                    if user.strip():
                        # Check individual user crontabs
                        code, out, err = self._run_command(f"crontab -u {user} -l 2>/dev/null")
                        if code == 0 and out:
                            for line in out.split('\n'):
                                line = line.strip()
                                if line and not line.startswith('#'):
                                    for indicator in suspicious_indicators:
                                        if indicator in line.lower():
                                            issues.append(f"User {user} cron: {line[:50]}...")
                                            break
            
            # Check system-wide cron directories
            cron_dirs = ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.monthly", "/etc/cron.weekly"]
            for cron_dir in cron_dirs:
                if os.path.exists(cron_dir):
                    try:
                        for file in os.listdir(cron_dir):
                            filepath = os.path.join(cron_dir, file)
                            if os.path.isfile(filepath):
                                with open(filepath, 'r') as f:
                                    content = f.read()
                                    for line in content.split('\n'):
                                        line = line.strip()
                                        if line and not line.startswith('#'):
                                            for indicator in suspicious_indicators:
                                                if indicator in line.lower():
                                                    issues.append(f"{cron_dir}/{file}: {line[:50]}...")
                                                    break
                    except:
                        continue
            
            # Check systemd timers
            code, out, err = self._run_command("systemctl list-timers --all")
            if code == 0:
                for line in out.split('\n'):
                    for indicator in suspicious_indicators:
                        if indicator in line.lower():
                            issues.append(f"Systemd timer: {line[:50]}...")
                            break
            
        except Exception as e:
            check.status = "UNKNOWN"
            check.details = f"Cannot check cron/systemd: {e}"
            return check
        
        if issues:
            check.status = "WARN"
            check.details = f"Found {len(issues)} suspicious cron/systemd entries"
            check.remediation_needed = True
        else:
            check.status = "PASS"
            check.details = "No suspicious cron/systemd timers found"
        
        return check
    
    def check_system_updates(self) -> ConfigCheck:
        """Check for system updates/available security upgrades"""
        check = ConfigCheck("system_updates", "System updates available", "MEDIUM")
        
        try:
            # Try apt for Debian/Ubuntu systems
            code, out, err = self._run_command("apt list --upgradable 2>/dev/null | wc -l")
            if code == 0 and out.strip():
                try:
                    upgradable_count = int(out.strip()) - 1 if int(out.strip()) > 0 else 0  # Subtract header line
                    if upgradable_count > 0:
                        check.status = "WARN"
                        check.details = f"{upgradable_count} system updates available"
                        check.remediation_needed = True
                    else:
                        check.status = "PASS"
                        check.details = "System is up to date"
                    return check
                except:
                    pass
            
            # Try apt-get for update check
            code, out, err = self._run_command("apt-get -s upgrade | grep -E '^[0-9]+ upgraded' | head -1")
            if code == 0 and out:
                if 'upgraded' in out:
                    # Extract number of upgrades
                    import re
                    match = re.search(r'(\d+) upgraded', out)
                    if match:
                        upgrade_count = int(match.group(1))
                        if upgrade_count > 0:
                            check.status = "WARN"
                            check.details = f"{upgrade_count} system updates available"
                            check.remediation_needed = True
                        else:
                            check.status = "PASS"
                            check.details = "System is up to date"
                        return check
            
            # Check if we can run apt update
            code, out, err = self._run_command("which apt")
            if code == 0:
                check.status = "UNKNOWN"
                check.details = "apt package manager detected but cannot check for updates (may need sudo)"
                return check
                
        except Exception as e:
            check.status = "UNKNOWN"
            check.details = f"Cannot check updates: {e}"
            return check
        
        # Fallback - check for other package managers
        package_managers = [
            ("yum", "yum check-update"),
            ("dnf", "dnf check-update"),
            ("pacman", "pacman -Qu")
        ]
        
        for pm_name, pm_command in package_managers:
            code, out, err = self._run_command(f"which {pm_name}")
            if code == 0:
                check.status = "UNKNOWN"
                check.details = f"{pm_name} package manager detected but cannot check for updates (may need sudo)"
                return check
        
        check.status = "UNKNOWN"
        check.details = "No supported package manager found or cannot check updates"
        return check
    
    def check_integrity_monitoring(self) -> ConfigCheck:
        """Check for integrity monitoring presence (AIDE, Tripwire, etc.)"""
        check = ConfigCheck("integrity_monitoring", "Integrity monitoring presence", "MEDIUM")
        
        # Check for AIDE
        aide_check = self._run_command("which aide")
        if aide_check[0] == 0:
            # Check if AIDE is configured
            if os.path.exists("/etc/aide/aide.conf") or os.path.exists("/etc/aide.conf"):
                check.status = "PASS"
                check.details = "AIDE integrity monitoring detected and configured"
                return check
        
        # Check for Tripwire
        tripwire_check = self._run_command("which tripwire")
        if tripwire_check[0] == 0:
            check.status = "PASS"
            check.details = "Tripwire integrity monitoring detected"
            return check
        
        # Check for Samhain
        samhain_check = self._run_command("which samhain")
        if samhain_check[0] == 0:
            check.status = "PASS"
            check.details = "Samhain integrity monitoring detected"
            return check
        
        # Check for systemd integrity checking
        systemd_check = self._run_command("systemctl list-unit-files | grep -c 'integrity'")
        if systemd_check[0] == 0 and systemd_check[1].strip() != "0":
            check.status = "PASS"
            check.details = "Systemd integrity checking detected"
            return check
        
        # Check for chkrootkit or rkhunter (basic rootkit detection)
        rootkit_tools = ["chkrootkit", "rkhunter"]
        for tool in rootkit_tools:
            tool_check = self._run_command(f"which {tool}")
            if tool_check[0] == 0:
                check.status = "WARN"
                check.details = f"{tool} rootkit detection found (basic security)"
                check.remediation_needed = True
                return check
        
        check.status = "FAIL"
        check.details = "No integrity monitoring system detected"
        check.remediation_needed = True
        return check

    def run_all_checks(self) -> List[ConfigCheck]:
        """Run all configuration checks"""
        results = []
        
        # Run individual checks
        checks_to_run = [
            self.check_firewall,
            self.check_dns_resolver,
            self.check_ssh_hardening,
            self.check_disk_encryption,
            self.check_vpn_status,
            self.check_exposed_services,
            self.check_swap_encryption,
            self.check_mac_randomization,
            self.check_auto_mount,
            self.check_selinux_status,
            self.check_shell_history,
            self.check_log_permissions,
            self.check_unauthorized_cron,    
            self.check_system_updates,         
            self.check_integrity_monitoring
            # Add more as you implement them
        ]
        
        for check_func in checks_to_run:
            try:
                result = check_func()
                results.append(result)
            except Exception as e:
                check = ConfigCheck("error", f"Check failed: {check_func.__name__}", "UNKNOWN")
                check.details = str(e)
                results.append(check)
        
        # Add placeholder checks for unimplemented ones
        remaining_checks = [c for c in self.checks if not any(c.check_id == r.check_id for r in results)]
        for check in remaining_checks:
            check.status = "UNKNOWN"
            check.details = "Not implemented yet"
            results.append(check)
        
        return results
    
    def create_snapshot(self, checks: List[ConfigCheck]) -> str:
        """Create a snapshot of current check results"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        snapshot_file = self.snapshot_dir / f"snapshot_{timestamp}.json"
        
        snapshot_data = {
            'timestamp': timestamp,
            'checks': [check.to_dict() for check in checks]
        }
        
        # Add hash for integrity
        snapshot_json = json.dumps(snapshot_data, indent=2, sort_keys=True)
        snapshot_hash = hashlib.sha256(snapshot_json.encode()).hexdigest()
        snapshot_data['signature'] = snapshot_hash
        
        with open(snapshot_file, 'w') as f:
            json.dump(snapshot_data, f, indent=2)
        
        return str(snapshot_file)
    
    def load_latest_snapshot(self) -> Dict:
        """Load the most recent snapshot"""
        snapshot_files = list(self.snapshot_dir.glob("snapshot_*.json"))
        if not snapshot_files:
            return {}
        
        latest = max(snapshot_files, key=lambda x: x.stat().st_mtime)
        with open(latest, 'r') as f:
            return json.load(f)
    
    def compare_snapshots(self, current: List[ConfigCheck], previous: Dict) -> Dict:
        """Compare current checks with previous snapshot"""
        changes = {
            'new_failures': [],
            'resolved_issues': [],
            'changed_status': []
        }
        
        if not previous or 'checks' not in previous:
            return changes
        
        prev_checks = {check['check_id']: check for check in previous['checks']}
        
        for current_check in current:
            check_id = current_check.check_id
            current_status = current_check.status
            
            if check_id in prev_checks:
                prev_status = prev_checks[check_id]['status']
                if current_status != prev_status:
                    if prev_status == "PASS" and current_status in ["FAIL", "WARN"]:
                        changes['new_failures'].append(current_check.check_id)
                    elif prev_status in ["FAIL", "WARN"] and current_status == "PASS":
                        changes['resolved_issues'].append(current_check.check_id)
                    changes['changed_status'].append({
                        'check_id': check_id,
                        'from': prev_status,
                        'to': current_status
                    })
        
        return changes

# Snapshot management functions
def list_snapshots(snapshot_dir="~/.privaware/snapshots"):
    """List all snapshots"""
    snapshot_path = Path(os.path.expanduser(snapshot_dir))
    snapshots = list(snapshot_path.glob("snapshot_*.json"))
    snapshots.sort(key=lambda x: x.stat().st_mtime, reverse=True)
    
    print("📸 Available Snapshots:")
    print("=" * 50)
    for snapshot in snapshots:
        timestamp = snapshot.stem.replace("snapshot_", "")
        size = snapshot.stat().st_size
        print(f"  {timestamp} ({size} bytes)")

def show_snapshot(snapshot_file, snapshot_dir="~/.privaware/snapshots"):
    """Show snapshot details"""
    snapshot_path = Path(os.path.expanduser(snapshot_dir)) / snapshot_file
    if not snapshot_path.exists():
        print(f"❌ Snapshot {snapshot_file} not found")
        return
    
    with open(snapshot_path, 'r') as f:
        data = json.load(f)
    
    print(f"📊 Snapshot: {snapshot_file}")
    print(f"⏰ Timestamp: {data.get('timestamp', 'Unknown')}")
    print(f"🔐 Signature: {data.get('signature', 'None')[:16]}...")
    print("\n📋 Check Results:")
    print("-" * 30)
    
    for check in data.get('checks', []):
        status_icon = {
            "PASS": "✅", "WARN": "⚠️", "FAIL": "❌", "UNKNOWN": "❓"
        }.get(check.get('status', 'UNKNOWN'), "❓")
        
        print(f"{status_icon} {check.get('check_id', 'Unknown'):20} [{check.get('status', 'UNKNOWN'):6}]")
        if check.get('details'):
            print(f"   {check.get('details')}")

# Example usage function
# Example usage function
def run_config_check(snapshot_dir="~/.privaware/snapshots", interval=30, once=False):
    """Main function to run config checks"""
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress
    from rich import box
    
    console = Console()
    
    while True:
        console.print(f"[bold blue][{datetime.now().strftime('%H:%M:%S')}][/bold blue] Running privacy configuration checks...")
        
        # Run all checks
        checker = ConfigChecker(snapshot_dir=snapshot_dir)
        
        # Show progress
        with Progress() as progress:
            task = progress.add_task("[green]Scanning system security...", total=15)
            checks = checker.run_all_checks()
            progress.update(task, completed=15)
        
        # Create snapshot
        snapshot_file = checker.create_snapshot(checks)
        console.print(f"[green]✓[/green] Snapshot saved: {snapshot_file}")
        
        # Compare with previous
        previous = checker.load_latest_snapshot()
        changes = checker.compare_snapshots(checks, previous)
        
        # Categorize checks by severity
        critical_issues = [c for c in checks if c.severity == "CRITICAL" and c.status in ["FAIL", "WARN"]]
        high_issues = [c for c in checks if c.severity == "HIGH" and c.status in ["FAIL", "WARN"]]
        medium_issues = [c for c in checks if c.severity == "MEDIUM" and c.status in ["FAIL", "WARN"]]
        low_issues = [c for c in checks if c.severity == "LOW" and c.status in ["FAIL", "WARN"]]
        passed_checks = [c for c in checks if c.status == "PASS"]
        unknown_checks = [c for c in checks if c.status == "UNKNOWN"]
        
        # Display summary
        console.print(Panel.fit("[bold]🛡️  PRIVAWARE SECURITY SCAN RESULTS[/bold]", border_style="blue"))
        
        # Security Score
        total_checks = len(checks)
        passed_count = len(passed_checks)
        security_score = int((passed_count / total_checks) * 100)
        
        score_color = "red" if security_score < 50 else "yellow" if security_score < 80 else "green"
        console.print(f"[bold]Security Score: [{score_color}]{security_score}%[/{score_color}][/bold]")
        console.print(f"Passed: [green]{passed_count}[/green] | Total: {total_checks}")
        
        # Display categorized results
        if critical_issues or high_issues:
            console.print("\n[bold red]🚨 CRITICAL/HIGH RISK ISSUES[/bold red]")
            console.print("[red]These issues require immediate attention![/red]")
            table = Table(box=box.ROUNDED, show_header=True, header_style="bold red")
            table.add_column("Issue", style="cyan", width=35)
            table.add_column("Status", style="red", width=12)
            table.add_column("Details", style="yellow", width=50)
            
            for issue in critical_issues + high_issues:
                status_icon = "❌" if issue.status == "FAIL" else "⚠️"
                table.add_row(issue.description, f"{status_icon} {issue.status}", issue.details[:80] + "..." if len(issue.details) > 80 else issue.details)
            console.print(table)
        
        if medium_issues:
            console.print("\n[bold yellow]⚠️  MEDIUM RISK ISSUES[/bold yellow]")
            table = Table(box=box.ROUNDED, show_header=True, header_style="bold yellow")
            table.add_column("Issue", style="cyan", width=35)
            table.add_column("Status", style="yellow", width=12)
            table.add_column("Details", style="white", width=50)
            
            for issue in medium_issues:
                status_icon = "❌" if issue.status == "FAIL" else "⚠️"
                table.add_row(issue.description, f"{status_icon} {issue.status}", issue.details[:80] + "..." if len(issue.details) > 80 else issue.details)
            console.print(table)
        
        if low_issues:
            console.print("\n[bold blue]ℹ️  LOW RISK ISSUES[/bold blue]")
            table = Table(box=box.ROUNDED, show_header=True, header_style="bold blue")
            table.add_column("Issue", style="cyan", width=35)
            table.add_column("Status", style="blue", width=12)
            table.add_column("Details", style="white", width=50)
            
            for issue in low_issues:
                status_icon = "❌" if issue.status == "FAIL" else "⚠️"
                table.add_row(issue.description, f"{status_icon} {issue.status}", issue.details[:80] + "..." if len(issue.details) > 80 else issue.details)
            console.print(table)
        
        # Show passed checks in a table
        if passed_checks:
            console.print(f"\n[bold green]✅ {len(passed_checks)} checks passed:[/bold green]")
            table = Table(box=box.SIMPLE, show_header=True, header_style="bold green")
            table.add_column("Passed Check", style="green")
            table.add_column("Description", style="cyan")
            
            for check in passed_checks:
                table.add_row(f"✓ {check.check_id}", check.description)
            console.print(table)
        
        # Show unknown checks in a table
        if unknown_checks:
            console.print(f"\n[bold #808080]❓ {len(unknown_checks)} checks unavailable:[/bold #808080]")  # Using hex color instead of "gray"
            table = Table(box=box.SIMPLE, show_header=True, header_style="bold #808080")  # Using hex color
            table.add_column("Unavailable Check", style="#808080")  # Using hex color
            table.add_column("Description", style="white")
            table.add_column("Reason", style="yellow")
            
            for check in unknown_checks:
                table.add_row(f"? {check.check_id}", check.description, check.details)
            console.print(table)
        
        # Show changes
        if changes['new_failures'] or changes['resolved_issues']:
            console.print("\n[bold magenta]🔄 Recent Changes:[/bold magenta]")
            if changes['new_failures']:
                console.print(f"   [red]New issues:[/red] {', '.join(changes['new_failures'])}")
            if changes['resolved_issues']:
                console.print(f"   [green]Fixed issues:[/green] {', '.join(changes['resolved_issues'])}")
        
        # Recommendations
        total_issues = len(critical_issues) + len(high_issues) + len(medium_issues) + len(low_issues)
        if total_issues > 0:
            console.print(f"\n[bold]💡 Quick Recommendations:[/bold]")
            if critical_issues:
                console.print("   🔴 Address critical issues first - they pose immediate security risks")
            if high_issues:
                console.print("   🟠 Fix high-risk issues to improve security posture")
            console.print(f"   🛠️  Run 'privaware --help' to see remediation options")
        
        if once:
            break
            
        console.print(f"\n[yellow]⏳ Next check in {interval} seconds...[/yellow]")
        console.print("[dim]Press Ctrl+C to stop monitoring[/dim]")
        time.sleep(interval)

if __name__ == "__main__":
    run_config_check(once=True)

