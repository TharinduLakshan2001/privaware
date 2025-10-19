# privaware_pkg/core/config_checker.py
"""
Config Checker: Privacy configuration monitoring and auditing.
Dynamically loads individual check modules from core/checks/.
"""
import os
import json
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Callable
import hashlib
import importlib.util
import pkgutil

# Import necessary classes and functions from the common models
from .config_models import ConfigCheck, run_command_simple
# Import AlertSender
try:
    from core.alerts import AlertSender
except ImportError:
    AlertSender = None
    print("Warning: Alert system (AlertSender) not available")


class ConfigChecker:
    """
    Orchestrates privacy configuration checks by dynamically loading them.
    """
    def __init__(self, snapshot_dir="~/.privaware/snapshots", profile="balanced", send_alerts=True):
        self.snapshot_dir = Path(os.path.expanduser(snapshot_dir))
        self.profile = profile
        self.send_alerts = send_alerts
        self.snapshot_dir.mkdir(parents=True, exist_ok=True)
        # Ensure the 'acknowledged' directory exists
        self.ack_dir = self.snapshot_dir.parent / "acknowledged"
        self.ack_dir.mkdir(parents=True, exist_ok=True)
        self.alert_sender = AlertSender() if send_alerts and AlertSender else None
        # Dynamically discover and load check functions
        self.check_functions = self._discover_check_functions()
        print(f"[ConfigChecker] Initialized. Found {len(self.check_functions)} check functions.")

    def _discover_check_functions(self) -> List[Callable[[], ConfigCheck]]:
        """Dynamically discover and import check functions from the checks package."""
        check_functions = []
        checks_package_name = 'core.checks' # Must match the actual package name

        try:
            # Import the checks package
            checks_package = importlib.import_module(checks_package_name)
            checks_package_path = checks_package.__path__

            # Iterate through modules in the checks package
            print(f"[ConfigChecker] Discovering checks in {checks_package_path}...")
            for importer, modname, ispkg in pkgutil.iter_modules(checks_package_path):
                if not ispkg and modname.startswith('check_'):
                    try:
                        # Import the module
                        full_module_name = f"{checks_package_name}.{modname}"
                        print(f"[ConfigChecker] Attempting to load module: {full_module_name}")
                        module = importlib.import_module(full_module_name)

                        # The function name should match the module name (e.g., check_firewall)
                        check_func_name = modname # e.g., 'check_firewall'
                        if hasattr(module, check_func_name):
                            func_obj = getattr(module, check_func_name)
                            if callable(func_obj):
                                check_functions.append(func_obj)
                                print(f"[ConfigChecker] Successfully loaded check function: {check_func_name}")
                            else:
                                print(f"Warning: {modname}.{check_func_name} is not callable. Skipping.")
                        else:
                            print(f"Warning: Module {modname} does not contain a function named '{check_func_name}'. Skipping.")
                    except Exception as e:
                        print(f"Error importing check module {modname}: {e}")
        except ImportError as e:
            print(f"Error importing checks package {checks_package_name}: {e}")
        except Exception as e:
            print(f"Unexpected error discovering checks: {e}")

        if not check_functions:
            print("Warning: No check functions were discovered. Please ensure check modules exist in core/checks/ and follow the naming convention (check_*.py with a function named check_*).")
        else:
            print(f"[ConfigChecker] Successfully discovered {len(check_functions)} check functions.")
        return check_functions

    # --- Remove all individual check_* methods (check_firewall, check_dns_resolver, etc.) ---
    # They are now in separate files in core/checks/.

    def _is_check_acknowledged(self, check_id: str) -> bool:
        """
        Internal helper to check if a specific check has been acknowledged.
        Looks for a marker file.
        """
        ack_marker_path = self.ack_dir / check_id
        return ack_marker_path.exists()

    def _acknowledge_check(self, check_id: str):
        """
        Internal helper to mark a specific check as acknowledged.
        Creates a marker file.
        """
        ack_marker_path = self.ack_dir / check_id
        ack_marker_path.touch() # Create an empty file as a marker
        print(f"[ConfigChecker] Check '{check_id}' has been acknowledged.")

    def _send_system_alert(self, failed_checks: List[ConfigCheck]):
        """Send system desktop notification"""
        if not failed_checks:
            return
        try:
            critical_count = len([c for c in failed_checks if c.severity == "CRITICAL"])
            high_count = len([c for c in failed_checks if c.severity == "HIGH"])
            title = "PrivAware Security Alert"
            message = f"🚨 {len(failed_checks)} security issues found"
            if critical_count > 0:
                message += f" | 🔴 {critical_count} critical"
            if high_count > 0:
                message += f" | 🟠 {high_count} high risk"
            subprocess.run(['notify-send', title, message], timeout=5, stderr=subprocess.DEVNULL)
        except Exception as e: # Catch broader exceptions
            # notify-send not available or other error
            # print(f"Could not send system alert: {e}") # Optional: log if needed
            pass

    def _send_email_alert(self, failed_checks: List[ConfigCheck]):
        """Send email alert with remediation options"""
        if not self.alert_sender or not failed_checks:
            return
        subject = f"PrivAware Security Alert - {len(failed_checks)} Issues Found"
        message_lines = [
            "🛡️ PRIVAWARE SECURITY ALERT",
            f"🕒 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"🚨 {len(failed_checks)} security issues detected:",
            ""
        ]
        for check in failed_checks:
            severity_icon = {
                "CRITICAL": "🔴",
                "HIGH": "🟠",
                "MEDIUM": "🟡",
                "LOW": "🔵"
            }.get(check.severity, "⚪")
            message_lines.append(f"{severity_icon} [{check.severity}] {check.description}")
            message_lines.append(f"   Details: {check.details}")
            if check.remediation_command:
                message_lines.append(f"   🔧 Fix: {check.remediation_command}")
            message_lines.append("")
        message_lines.append("🔧 To fix issues automatically, run:")
        message_lines.append("   privaware --check-config --auto-fix")
        message_lines.append("")
        message_lines.append("📝 To see detailed report:")
        message_lines.append("   privaware --check-config --once")
        message = "\n".join(message_lines)
        try:
            success = self.alert_sender.send_alert(subject, message)
            if success:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] 📧 Security alert sent successfully")
        except Exception as e:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] ❌ Error sending alert: {e}")

    def _send_alerts(self, checks: List[ConfigCheck]):
        """Send both system and email alerts"""
        # Filter out acknowledged risks from alerts, as they are accepted
        # You might want to send a different kind of alert for acknowledged risks
        # but for now, we exclude them from the main failure alerts.
        failed_checks = [c for c in checks if c.status in ["FAIL", "WARN"] and not c.acknowledged]
        if not failed_checks:
            return
        self._send_system_alert(failed_checks)
        if self.send_alerts:
            self._send_email_alert(failed_checks)

    def run_all_checks(self) -> List[ConfigCheck]:
        """Run all configuration checks discovered in the checks package."""
        results = []

        # --- Run dynamically discovered check functions ---
        print(f"[ConfigChecker] Running {len(self.check_functions)} discovered checks...")
        for check_func in self.check_functions:
            try:
                # Call the check function, expecting it to return a ConfigCheck object
                result = check_func()
                # Basic validation - check if it looks like a ConfigCheck object
                # Using isinstance might be tricky if classes are defined differently,
                # so we check for essential attributes.
                if hasattr(result, 'check_id') and hasattr(result, 'status'):
                     # If it's already a ConfigCheck object, append directly
                    results.append(result)
                    print(f"[ConfigChecker] Check '{result.check_id}' completed with status '{result.status}'.")
                else:
                    print(f"Warning: Check function {check_func.__name__} did not return a valid ConfigCheck-like object.")
                    # Create an error check
                    error_check = ConfigCheck("error", f"Check failed: {check_func.__name__}", "UNKNOWN")
                    error_check.details = "Function did not return a ConfigCheck object."
                    results.append(error_check)
            except Exception as e:
                # Create a ConfigCheck object to represent the error
                error_check = ConfigCheck("error", f"Check failed: {check_func.__name__}", "UNKNOWN")
                error_check.details = str(e)
                results.append(error_check)
                print(f"[ConfigChecker] Error running check {check_func.__name__}: {e}")

        # --- NEW: Check for acknowledged status AFTER running checks ---
        for check in results:
            # Only check for acknowledgement if the check failed or warned
            # and it hasn't been acknowledged already by the check itself
            if check.status in ["FAIL", "WARN"] and not check.acknowledged:
                if self._is_check_acknowledged(check.check_id):
                    check.acknowledged = True
                    # Optionally modify details to indicate it's acknowledged
                    # This makes it clear in the UI report
                    check.details += " (Risk acknowledged by user)"

        # --- Send alerts for failed checks ---
        # The _send_alerts method now filters out acknowledged risks
        self._send_alerts(results)
        return results

    def auto_fix_issues(self, checks: List[ConfigCheck]) -> List[ConfigCheck]:
        """Attempt to automatically fix issues that have remediation commands"""
        fixed_checks = []
        for check in checks:
            if check.remediation_needed and check.remediation_command:
                try:
                    print(f"🔧 Attempting to fix: {check.description}")
                    code, out, err = run_command_simple(check.remediation_command, shell=True)
                    if code == 0:
                        check.remediation_result = "SUCCESS"
                        check.remediation_attempted = True
                        print(f"✅ Fixed: {check.description}")
                    else:
                        check.remediation_result = f"FAILED: {err}"
                        check.remediation_attempted = True
                        print(f"❌ Failed to fix: {check.description} - {err}")
                except Exception as e:
                    check.remediation_result = f"ERROR: {str(e)}"
                    check.remediation_attempted = True
                    print(f"❌ Error fixing {check.description}: {e}")
                fixed_checks.append(check)
        return fixed_checks

    def create_snapshot(self, checks: List[ConfigCheck]) -> str:
        """Create a snapshot of current check results"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        snapshot_file = self.snapshot_dir / f"snapshot_{timestamp}.json"
        snapshot_data = {
            'timestamp': timestamp,
            'checks': [check.to_dict() for check in checks]
        }
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

# --- Keep the run_config_check function largely as is, but update imports ---
# Enhanced run_config_check function
def run_config_check(snapshot_dir="~/.privaware/snapshots", interval=30, once=False, send_alerts=True, auto_fix=False):
    """Main function to run config checks"""
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress
    from rich import box

    console = Console()
    while True:
        console.print(f"[bold blue][{datetime.now().strftime('%H:%M:%S')}][/bold blue] Running privacy configuration checks...")

        # Run all checks using the refactored ConfigChecker
        checker = ConfigChecker(snapshot_dir=snapshot_dir, send_alerts=send_alerts)

        # Show progress
        with Progress() as progress:
            # Use the actual number of discovered functions for the progress bar
            num_checks = len(checker.check_functions) if checker.check_functions else 15 # Fallback if discovery failed
            task = progress.add_task("[green]Scanning system security...", total=num_checks)
            checks = checker.run_all_checks()
            progress.update(task, completed=num_checks) # Update to completed

        # Create snapshot
        snapshot_file = checker.create_snapshot(checks)
        console.print(f"[green]✓[/green] Snapshot saved: {snapshot_file}")

        # Auto-fix if requested
        if auto_fix:
            failed_checks = [c for c in checks if c.status in ["FAIL", "WARN"] and c.remediation_command]
            if failed_checks:
                console.print(Panel("🔧 Auto-fixing security issues...", style="bold yellow"))
                fixed_checks = checker.auto_fix_issues(failed_checks)
                if fixed_checks:
                    console.print(f"[green]✅ Attempted to fix {len(fixed_checks)} issues[/green]")
                
                # Re-run checks to get updated status after fixes
                console.print(f"[yellow]🔄 Re-running checks to verify fixes...[/yellow]")
                checks = checker.run_all_checks()  # This will update the checks with new status

        # Compare with previous
        previous = checker.load_latest_snapshot()
        changes = checker.compare_snapshots(checks, previous)

        # Categorize checks by severity
        # --- NEW: Separate acknowledged risks ---
        acknowledged_risks = [c for c in checks if c.acknowledged]
        # --- Filter out acknowledged risks from main issue lists for display ---
        critical_issues = [c for c in checks if c.severity == "CRITICAL" and c.status in ["FAIL", "WARN"] and not c.acknowledged]
        high_issues = [c for c in checks if c.severity == "HIGH" and c.status in ["FAIL", "WARN"] and not c.acknowledged]
        medium_issues = [c for c in checks if c.severity == "MEDIUM" and c.status in ["FAIL", "WARN"] and not c.acknowledged]
        low_issues = [c for c in checks if c.severity == "LOW" and c.status in ["FAIL", "WARN"] and not c.acknowledged]
        
        # Include acknowledged risks in passed/unknown/error counts for overall stats,
        # or treat them separately. Let's treat them as "handled" for the main score.
        passed_checks = [c for c in checks if c.status == "PASS"] # This can include acknowledged passes
        # Separate actual UNKNOWN results from ERROR results (those with check_id == "error")
        actual_unknown_checks = [c for c in checks if c.status == "UNKNOWN" and c.check_id != "error"]
        error_checks = [c for c in checks if c.check_id == "error"]


        # Display summary
        console.print(Panel.fit("[bold]🛡️  PRIVAWARE SECURITY SCAN RESULTS[/bold]", border_style="blue"))

        # Security Score (exclude errors, optionally exclude acknowledged risks from penalty)
        # Option 1: Score based only on non-error, non-acknowledged checks
        # non_ack_non_error_checks = [c for c in checks if c.check_id != "error" and not c.acknowledged]
        # passed_non_ack_count = len([c for c in non_ack_non_error_checks if c.status == "PASS"])
        # total_non_ack_checks = len(non_ack_non_error_checks)
        # security_score = int((passed_non_ack_count / total_non_ack_checks) * 100) if total_non_ack_checks > 0 else 0
        
        # Option 2: Simpler score, just based on all non-error checks
        non_error_checks = [c for c in checks if c.check_id != "error"]
        passed_count = len([c for c in non_error_checks if c.status == "PASS"])
        total_checks = len(non_error_checks)
        security_score = int((passed_count / total_checks) * 100) if total_checks > 0 else 0
        
        score_color = "red" if security_score < 50 else "yellow" if security_score < 80 else "green"
        console.print(f"[bold]Security Score: [{score_color}]{security_score}%[/{score_color}][/bold]")
        console.print(f"Passed: [green]{passed_count}[/green] | Total: {total_checks}")
        if acknowledged_risks:
             console.print(f"Acknowledged Risks: [bold #808080]{len(acknowledged_risks)}[/bold #808080]") # Hex color for grey

        # --- Display categorized results (similar logic for each category) ---
        # Critical/High Issues (Non-Acknowledged)
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

        # Medium Issues (Non-Acknowledged)
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

        # Low Issues (Non-Acknowledged)
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

        # --- NEW: Show acknowledged risks ---
        if acknowledged_risks:
            console.print(f"\n[bold #808080]⚠️  {len(acknowledged_risks)} Acknowledged Risks:[/bold #808080]") # Using hex color for grey
            table = Table(box=box.ROUNDED, show_header=True, header_style="bold #808080") # Using hex color
            table.add_column("Acknowledged Risk", style="#808080") # Using hex color
            table.add_column("Description", style="white")
            table.add_column("Status", style="yellow")
            table.add_column("Details", style="white")
            for risk in acknowledged_risks:
                status_icon = "❌" if risk.status == "FAIL" else "⚠️"
                # Truncate details if too long, but indicate it's acknowledged
                details_display = risk.details[:80] + "..." if len(risk.details) > 80 else risk.details
                table.add_row(
                    f"✓ {risk.check_id}", # Tick mark to indicate it was checked/processed
                    risk.description,
                    f"{status_icon} {risk.status} (ACK)",
                    details_display
                )
            console.print(table)

        # Show unknown checks in a table
        if actual_unknown_checks:
            console.print(f"\n[bold #808080]❓ {len(actual_unknown_checks)} checks unavailable:[/bold #808080]") # Using hex color instead of "gray"
            table = Table(box=box.SIMPLE, show_header=True, header_style="bold #808080") # Using hex color
            table.add_column("Unavailable Check", style="#808080") # Using hex color
            table.add_column("Description", style="white")
            table.add_column("Reason", style="yellow")
            for check in actual_unknown_checks:
                table.add_row(f"? {check.check_id}", check.description, check.details)
            console.print(table)

         # Show error checks in a table
        if error_checks:
            console.print(f"\n[bold red]❌ {len(error_checks)} checks failed to run:[/bold red]")
            table = Table(box=box.SIMPLE, show_header=True, header_style="bold red")
            table.add_column("Failed Check/Error", style="red")
            table.add_column("Details", style="white")
            for check in error_checks:
                # Details should contain the error message
                 table.add_row(check.description, check.details)
            console.print(table)


        # Show changes
        if changes['new_failures'] or changes['resolved_issues']:
            console.print("\n[bold magenta]🔄 Recent Changes:[/bold magenta]")
            if changes['new_failures']:
                console.print(f"   [red]New issues:[/red] {', '.join(changes['new_failures'])}")
            if changes['resolved_issues']:
                console.print(f"   [green]Fixed issues:[/green] {', '.join(changes['resolved_issues'])}")

        # Recommendations
        # Only count non-acknowledged issues for recommendations
        total_issues = len(critical_issues) + len(high_issues) + len(medium_issues) + len(low_issues)
        if total_issues > 0:
            console.print(f"\n[bold]💡 Quick Recommendations:[/bold]")
            if critical_issues:
                console.print("   🔴 Address critical issues first - they pose immediate security risks")
            if high_issues:
                console.print("   🟠 Fix high-risk issues to improve security posture")
            console.print(f"   🛠️  Run 'privaware --help' to see remediation options")
        elif acknowledged_risks:
             # If all issues are acknowledged, give a different message
             console.print(f"\n[bold]💡 Status:[/bold]")
             console.print("   [bold #808080]All identified risks have been acknowledged.[/bold #808080] Review periodically.")

        if once:
            break

        console.print(f"\n[yellow]⏳ Next check in {interval} seconds...[/yellow]")
        console.print("[dim]Press Ctrl+C to stop monitoring[/dim]")
        time.sleep(interval)


# Add these functions to the end of your existing core/config_checker.py file

def list_snapshots(snapshot_dir="~/.privaware/snapshots"):
    """List available snapshots"""
    from rich.console import Console
    from rich.table import Table
    console = Console()
    
    import os
    from pathlib import Path
    from datetime import datetime
    
    snapshot_dir = Path(os.path.expanduser(snapshot_dir))
    snapshots = list(snapshot_dir.glob("snapshot_*.json"))
    
    if not snapshots:
        console.print("[yellow]No snapshots found.[/yellow]")
        return
    
    table = Table(title="[bold blue]Available Snapshots[/bold blue]")
    table.add_column("Filename", style="cyan")
    table.add_column("Date", style="green")
    table.add_column("Size", style="yellow")
    
    for snapshot in sorted(snapshots, key=lambda x: x.stat().st_mtime, reverse=True):
        stat = snapshot.stat()
        table.add_row(
            snapshot.name,
            datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
            f"{stat.st_size} bytes"
        )
    
    console.print(table)

def show_snapshot(snapshot_name, snapshot_dir="~/.privaware/snapshots"):
    """Show details of a specific snapshot"""
    from rich.console import Console
    from rich.table import Table
    console = Console()
    
    import os
    import json
    from pathlib import Path
    from datetime import datetime
    
    snapshot_dir = Path(os.path.expanduser(snapshot_dir))
    
    if snapshot_name == "latest":
        snapshots = list(snapshot_dir.glob("snapshot_*.json"))
        if not snapshots:
            console.print("[red]No snapshots found.[/red]")
            return
        snapshot_path = max(snapshots, key=lambda x: x.stat().st_mtime)
    else:
        snapshot_path = snapshot_dir / f"snapshot_{snapshot_name}.json"
        if not snapshot_path.exists():
            console.print(f"[red]Snapshot {snapshot_name} not found.[/red]")
            return
    
    with open(snapshot_path, 'r') as f:
        data = json.load(f)
    
    console.print(f"[bold blue]Snapshot: {snapshot_path.name}[/bold blue]")
    console.print(f"[green]Generated: {data['timestamp']}[/green]")
    
    # Count results
    checks = data['checks']
    passed = len([c for c in checks if c['status'] == 'PASS'])
    failed = len([c for c in checks if c['status'] in ['FAIL', 'WARN']])
    unknown = len([c for c in checks if c['status'] == 'UNKNOWN'])
    
    console.print(f"[bold]Summary:[/bold] {passed} passed, {failed} failed, {unknown} unknown")
    
    # Show failed checks
    if failed > 0:
        table = Table(title="[bold red]Failed Checks[/bold red]")
        table.add_column("Check", style="cyan")
        table.add_column("Severity", style="yellow")
        table.add_column("Details", style="white")
        
        for check in checks:
            if check['status'] in ['FAIL', 'WARN']:
                table.add_row(
                    check['description'],
                    check['severity'],
                    check['details'][:100] + "..." if len(check['details']) > 100 else check['details']
                )
        
        console.print(table)
