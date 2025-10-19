#!/usr/bin/env python3
"""
Main CLI entry point for PrivAware.
"""

import argparse
import sys
import subprocess
import importlib.util
import os
import time
from pathlib import Path

# Add the parent directory to sys.path to make imports work
sys.path.insert(0, str(Path(__file__).parent))

from core.audit import Auditor
from core.monitor import SystemMonitor
from core.log_monitor import LogMonitor
from core.filewatch import FileWatcher
from core.servicecheck import ServiceChecker
from core.alerts import send_test_alert
from core.banner import display_banner

# Import the new real-time file watcher with better error handling
try:
    from core.file_realtime_watch import CoolFileWatcherManager
except ImportError as e:
    print(f"Import error: {e}")
    try:
        # Try alternative import path
        sys.path.append(str(Path(__file__).parent / "core"))
        from file_realtime_watch import CoolFileWatcherManager
    except ImportError:
        CoolFileWatcherManager = None
        print("Warning: Real-time file watcher not available")

# In privaware.py, add this import with other imports:
from core.enhanced_dashboard import run_enhanced_dashboard

def check_and_install_requirements():
    required = ["psutil", "watchdog", "rich", "python-dotenv"]
    for pkg in required:
        if importlib.util.find_spec(pkg) is None:
            print(f"[PrivAware] Installing missing package: {pkg}")
            subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])

def run_setup():
    setup_path = os.path.join(os.path.dirname(__file__), "core", "setup.py")
    if os.path.exists(setup_path):
        subprocess.run([sys.executable, setup_path])
    else:
        print("[PrivAware] setup.py not found!")

def prompt_background_service():
    consent = input("Do you want PrivAware to run in the background on startup? (y/n): ").strip().lower()
    if consent == 'y':
        # Try to set up systemd service
        service_path = os.path.join(os.path.dirname(__file__), "privaware_agent.service")
        if os.path.exists(service_path):
            print("[PrivAware] Setting up systemd service...")
            subprocess.run(["sudo", "cp", service_path, "/etc/systemd/system/"])
            subprocess.run(["sudo", "systemctl", "daemon-reload"])
            subprocess.run(["sudo", "systemctl", "enable", "privaware_agent"])
            subprocess.run(["sudo", "systemctl", "start", "privaware_agent"])
            print("[PrivAware] Service installed and started.")
        else:
            print("[PrivAware] Service file not found.")
    else:
        print("[PrivAware] Background service not enabled.")

def run_audit():
    """Run system audit checks."""
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress
    
    auditor = Auditor()
    checks = auditor.checks if hasattr(auditor, 'checks') else []
    console = Console()
    table = Table(title="[bold cyan]PrivAware Audit Results[/bold cyan]", show_lines=True)
    table.add_column("Check", style="bold")
    table.add_column("Result", style="bold")
    
    with Progress(transient=True) as progress:
        task = progress.add_task("[green]Running audit checks...", total=len(checks))
        results = auditor.run_all()
        progress.update(task, completed=len(checks))

    # Display results properly
    for check, res in results.items():
        # Use the built-in formatter
        color, summary = Auditor.format_check_for_cli(res)
        details = res.get("details", [])
        display = summary
        if details and summary != "OK":
            snippet = "\n".join(str(x) for x in (details[:3]))
            if len(details) > 3:
                snippet += "\n..."
            display = f"{summary}\n{snippet}"
        table.add_row(f"[{color}]{check}", f"[{color}]{display}")
    console.print(table)

def run_monitor(realtime=False, interval=5):
    """Check system health with optional real-time monitoring."""
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    import time
    from datetime import datetime, timedelta
    import io
    from contextlib import redirect_stdout
    
    console = Console()
    
    if realtime:
        # Real-time monitoring mode with email alerts
        from core.monitor import SystemMonitor
        from core.alerts import AlertSender
        
        def alert_handler(alert):
            console.print(f"[bold red]🚨 ALERT: {alert}[/bold red]")
        
        monitor = SystemMonitor(alert_callback=alert_handler)
        alert_sender = AlertSender()
        
        console.print(Panel("[bold green]🚀 Starting Real-Time System Monitor[/bold green]", 
                           border_style="green"))
        console.print(f"[yellow]Monitoring interval: {interval} seconds | Email alert interval: 60 seconds[/yellow]")
        console.print("[yellow]Press Ctrl+C to stop[/yellow]\n")
        
        last_alert_time = datetime.now() - timedelta(seconds=60)  # Send first alert immediately
        
        try:
            while True:
                # Check for alerts continuously
                metrics = monitor.run_all()
                
                # Send email alert every minute
                current_time = datetime.now()
                if (current_time - last_alert_time).total_seconds() >= 60:
                    # Create status table in memory
                    table = Table(title=f"📊 System Status Report - {current_time.strftime('%Y-%m-%d %H:%M:%S')}")
                    table.add_column("Metric", style="cyan")
                    table.add_column("Value", style="green")
                    table.add_column("Status", style="yellow")
                    
                    # Add metrics to table in proper order
                    metric_order = ['cpu', 'memory', 'disk', 'load', 'temperature']
                    for key in metric_order:
                        if key in metrics:
                            value = metrics[key]
                            if isinstance(value, dict):
                                usage = value.get('usage', 0)
                                alert = value.get('alert', False)
                                status = "⚠ ALERT" if alert else "✓ OK"
                                table.add_row(
                                    key.upper(),
                                    f"{usage:.1f}%",
                                    status
                                )
                    
                    # Capture table output as string
                    string_buffer = io.StringIO()
                    table_console = Console(file=string_buffer, width=80)
                    table_console.print(table)
                    table_string = string_buffer.getvalue()
                    
                    # Prepare email content
                    subject = f"PrivAware System Status - {current_time.strftime('%Y-%m-%d %H:%M')}"
                    message = f"PrivAware System Monitoring Report\n\n{table_string}\nGenerated by PrivAware Security Toolkit"
                    
                    # Send email alert
                    try:
                        success = alert_sender.send_alert(subject, message)
                        if success:
                            console.print(f"[green]📧 Email alert sent at {current_time.strftime('%H:%M:%S')}[/green]")
                        else:
                            console.print(f"[red]❌ Failed to send email alert at {current_time.strftime('%H:%M:%S')}[/red]")
                    except Exception as e:
                        console.print(f"[red]❌ Error sending email: {e}[/red]")
                    
                    # Also display on console
                    console.print(table)
                    console.print("")  # Empty line for spacing
                    last_alert_time = current_time
                
                time.sleep(interval)
                
        except KeyboardInterrupt:
            console.print("\n[green]👋 Real-time monitoring stopped.[/green]")
    else:
        # One-time check mode
        from core.monitor import SystemMonitor
        monitor = SystemMonitor()
        metrics = monitor.run_all()
        
        table = Table(title="[bold blue]🖥️  System Health Monitor[/bold blue]")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")
        table.add_column("Status", style="yellow")
        
        # Display in specific order
        metric_order = ['cpu', 'memory', 'disk', 'load', 'temperature']
        for key in metric_order:
            if key in metrics:
                value = metrics[key]
                if isinstance(value, dict):
                    usage = value.get('usage', 0)
                    alert = value.get('alert', False)
                    status = "[red bold]⚠ ALERT[/red bold]" if alert else "[green]✓ OK[/green]"
                    table.add_row(
                        key.upper(),
                        f"{usage:.1f}%",
                        status
                    )
        
        console.print(table)

def run_log_monitor():
    """Parse logs for suspicious activity."""
    from rich.console import Console
    from rich.table import Table
    
    console = Console()
    log_monitor = LogMonitor()
    
    print("[PrivAware] Analyzing system logs for suspicious activity...")
    suspicious_events = log_monitor.analyze_logs()
    
    if suspicious_events:
        table = Table(title="[bold red]Suspicious Log Events[/bold red]")
        table.add_column("Timestamp", style="cyan")
        table.add_column("Event", style="yellow")
        table.add_column("Details", style="red")
        
        for event in suspicious_events[:10]:  # Show top 10
            table.add_row(
                event.get('timestamp', 'N/A'),
                event.get('type', 'Unknown'),
                event.get('message', 'No details')
            )
        
        console.print(table)
    else:
        console.print("[green]No suspicious activity found in logs.[/green]")

def run_file_watch():
    """Monitor sensitive files for changes."""
    from rich.console import Console
    console = Console()
    
    console.print("[bold yellow]Starting file change monitoring...[/bold yellow]")
    console.print("[yellow]Monitoring: /etc/passwd, /etc/shadow, ~/.ssh/authorized_keys[/yellow]")
    console.print("[yellow]Press Ctrl+C to stop.[/yellow]")
    
    watcher = FileWatcher()
    try:
        watcher.start_monitoring()
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        console.print("\n[red]Stopping file monitoring...[/red]")
        watcher.stop_monitoring()

def run_realtime_file_watch():
    """Monitor file system in real-time with detailed alerts."""
    from rich.console import Console
    console = Console()
    
    if CoolFileWatcherManager is None:
        console.print("[red]Error: Real-time file watcher not available.[/red]")
        console.print("[yellow]Make sure all dependencies are installed and the module is accessible.[/yellow]")
        return
    
    console.print("[bold green]🚀 Starting PrivAware Real-Time File Monitor[/bold green]")
    console.print("[bold blue]===========================================[/bold blue]")
    
    # Configure watch paths - focus on user areas for user monitoring
    watch_paths = [
        "/home",           # User home directories
        "/tmp"             # Temporary files
    ]
    
    watcher_manager = CoolFileWatcherManager(watch_paths, [])
    
    try:
        watcher_manager.start_monitoring()
        console.print("[green]🔥 Monitoring active! Try creating/modifying files in your home directory...[/green]")
        console.print("[yellow]💡 User CRUD operations will trigger alerts[/yellow]")
        console.print("[yellow]💡 System activity is monitored silently[/yellow]")
        console.print("[red]💡 Press Ctrl+C to stop monitoring[/red]\n")
        
        # Keep running
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        console.print("\n[bold red]⚠️  Received interrupt signal[/bold red]")
        watcher_manager.stop_monitoring()
    except Exception as e:
        console.print(f"[bold red]❌ Error: {e}[/bold red]")
        watcher_manager.stop_monitoring()

def run_service_check():
    """Check status of critical services with advanced monitoring."""
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress
    
    console = Console()
    
    console.print("[bold blue]🔍 Checking service status...[/bold blue]")
    
    # Try to import the new advanced service checker
    try:
        from core.servicecheck import AdvancedServiceMonitor
        service_checker = AdvancedServiceMonitor()  # Use the new advanced checker
        results = service_checker.check_all_services()
        
        # Get health score
        health = service_checker.get_health_score(results)
        
        # Display health score
        health_color = "red" if health['critical_score'] < 50 else "yellow" if health['critical_score'] < 80 else "green"
        console.print(Panel(
            f"[bold]System Health Score: [green]{health['overall_score']}%[/green] | "
            f"Critical: [{health_color}]{health['critical_score']}%[/bold]",
            title="Health Status"
        ))
        
        # Categorize services for better display
        categorized = service_checker.categorize_services(results)
        
        # Create tables for each category
        for category, services in categorized.items():
            if services:  # Only show categories that have services
                table = Table(title=f"[bold blue]{category.upper()} SERVICES[/bold blue]")
                table.add_column("Service", style="cyan")
                table.add_column("Status", style="green")
                table.add_column("Details", style="yellow")
                
                for service, status in services.items():
                    status_icon = "🟢" if status['status'] == 'RUNNING' else "🔴"
                    status_color = "green" if status['status'] == 'RUNNING' else "red"
                    
                    details = status['message']
                    if status['uptime'] > 0:
                        details += f" | Uptime: {status['uptime']:.0f}s"
                    if status['processes']:
                        details += f" | Processes: {len(status['processes'])}"
                    
                    table.add_row(
                        service, 
                        f"[{status_color}]{status_icon} {status['status']}[/{status_color}]", 
                        details
                    )
                
                console.print(table)
        
        # Show critical services summary
        critical_table = Table(title="[bold red]🚨 CRITICAL SERVICES[/bold red]")
        critical_table.add_column("Service", style="cyan")
        critical_table.add_column("Status", style="green")
        critical_table.add_column("Uptime", style="yellow")
        
        for service in service_checker.critical_services:
            if service in results:
                status = results[service]
                status_icon = "🟢" if status['status'] == 'RUNNING' else "🔴"
                uptime = f"{status['uptime']:.0f}s" if status['uptime'] > 0 else "N/A"
                critical_table.add_row(
                    service,
                    f"[red]{status_icon} {status['status']}[/red]",
                    uptime
                )
        
        console.print(critical_table)
        
        # Show system health report
        console.print(Panel(
            service_checker.get_system_health_report(),
            title="📋 System Health Report",
            expand=False
        ))
        
    except ImportError:
        # Fallback to the original service checker
        service_checker = ServiceChecker()
        services = ["sshd", "dnsmasq", "nginx"]  # Default services
        
        results = service_checker.check_services(services)
        
        table = Table(title="[bold blue]Service Status[/bold blue]")
        table.add_column("Service", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("Details", style="yellow")
        
        for service, result in results.items():
            status = result.get('status', 'UNKNOWN')
            details = result.get('message', 'No details')
            status_color = "green" if status == "RUNNING" else "red"
            table.add_row(service, f"[{status_color}]{status}[/{status_color}]", details)
        
        console.print(table)

def run_test_alert():
    """Send a test alert email."""
    from rich.console import Console
    console = Console()
    
    console.print("[bold yellow]Sending test alert...[/bold yellow]")
    try:
        send_test_alert()
        console.print("[green]✅ Test alert sent successfully![/green]")
    except Exception as e:
        console.print(f"[red]❌ Failed to send test alert: {e}[/red]")

def main():
    # Display banner first
    display_banner()
    
    parser = argparse.ArgumentParser(
        description="PrivAware CLI - Linux Privacy & Security Toolkit",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  privaware --audit                    # Run system security audit
  privaware --monitor                  # Check system health metrics
  privaware --realtime-monitor         # Real-time system monitoring
  privaware --check-config             # Privacy configuration monitoring
  privaware --filewatch                # Monitor sensitive file changes
  privaware --realtime-watch           # Real-time file system monitoring
  privaware --logs                     # Analyze system logs for threats
  privaware --servicecheck             # Check status of critical services
  privaware --test-alert               # Send a test alert email
  privaware --snapshot-list            # List configuration snapshots
  privaware --snapshot-show latest     # Show latest snapshot

Monitoring:
  --monitor --realtime-monitor         # System health monitoring
  --check-config --once                # One-time privacy check
  --check-config --interval 60         # Check every minute
"""
    )
    
    # Setup and Testing
    setup_group = parser.add_argument_group('Setup & Testing')
    setup_group.add_argument('--setup', action='store_true', help='Run initial setup and configuration')
    setup_group.add_argument('--test-alert', action='store_true', help='Send a test alert notification')
    
    # System Monitoring
    monitor_group = parser.add_argument_group('System Monitoring')
    monitor_group.add_argument('--monitor', action='store_true', help='Check current system health (CPU, memory, disk)')
    monitor_group.add_argument('--realtime-monitor', action='store_true', help='Real-time system health monitoring')
    monitor_group.add_argument('--monitor-interval', type=int, default=5, metavar='SECONDS',
                              help='Monitoring interval in seconds (default: 5)')
    
    # Security Audit
    audit_group = parser.add_argument_group('Security Audit')
    audit_group.add_argument('--audit', action='store_true', help='Run comprehensive system security audit')
    audit_group.add_argument('--servicecheck', action='store_true', help='Check status of critical services')
    
    # Privacy Configuration
    privacy_group = parser.add_argument_group('Privacy Configuration')
    privacy_group.add_argument('--check-config', action='store_true', help='Run privacy configuration monitoring')
    privacy_group.add_argument('--interval', type=int, default=30, metavar='SECONDS',
                              help='Check interval in seconds (default: 30)')
    privacy_group.add_argument('--snapshot-dir', default='~/.privaware/snapshots', metavar='PATH',
                              help='Snapshot directory')
    privacy_group.add_argument('--once', action='store_true', help='Run single check instead of continuous monitoring')
    privacy_group.add_argument('--snapshot-list', action='store_true', help='List available configuration snapshots')
    privacy_group.add_argument('--snapshot-show', metavar='SNAPSHOT',
                              help='Show specific snapshot details')
    privacy_group.add_argument('--no-alerts', action='store_true', help='Disable email alerts')
    privacy_group.add_argument('--auto-fix', action='store_true', help='Automatically fix security issues when detected')
    
    # File & Log Monitoring
    file_group = parser.add_argument_group('File & Log Monitoring')
    file_group.add_argument('--filewatch', action='store_true', help='Monitor sensitive files for changes')
    file_group.add_argument('--realtime-watch', action='store_true', help='Real-time file system monitoring with alerts')
    file_group.add_argument('--logs', action='store_true', help='Parse logs for suspicious activity')

    # Device Monitoring
    device_group = parser.add_argument_group('Device Monitoring')
    device_group.add_argument('--dmonitor', action='store_true', 
                             help='Start real-time monitoring for USB/storage device connections')

    # Other
    parser.add_argument('-v', '--version', action='version', version='PrivAware 1.0.0')

    args = parser.parse_args()

    check_and_install_requirements()

    # Auto-run setup if .env is missing
    env_path = os.path.join(os.path.dirname(__file__), ".env")
    if (args.setup or not os.path.exists(env_path)):
        print("[PrivAware] Running setup...")
        run_setup()
        prompt_background_service()
        return

    # Run selected modules - Make sure args is defined before using it
    if args.audit:
        run_audit()
    
    if args.monitor or args.realtime_monitor:
        if args.realtime_monitor:
            # Then in the main() function, replace the existing realtime-monitor handling:
            # Find where you handle args.realtime_monitor and replace it with:
            run_enhanced_dashboard()
        else:
            run_monitor()
    
    # Add the new config check functionality
    if args.check_config:
        from core.config_checker import run_config_check
        run_config_check(
            snapshot_dir=args.snapshot_dir,
            interval=args.interval,
            once=args.once,
            send_alerts=not args.no_alerts,  # Use the --no-alerts flag
            auto_fix=args.auto_fix
        )
    
    if args.snapshot_list:
        from core.config_checker import list_snapshots
        list_snapshots(snapshot_dir=args.snapshot_dir)

    if args.snapshot_show:
        from core.config_checker import show_snapshot
        show_snapshot(args.snapshot_show, snapshot_dir=args.snapshot_dir)
        
    if args.logs:
        run_log_monitor()
        
    if args.filewatch:
        run_file_watch()
        
    if args.realtime_watch:
        run_realtime_file_watch()
        
    if args.servicecheck:
        run_service_check()
        
    if args.test_alert:
        run_test_alert()
        
    # Add the new device connection monitoring functionality
    if args.dmonitor: 
        try:
            from core.device_connection_monitor import DeviceConnectionMonitor
            print("[PrivAware] Launching Device Connection Monitor (--dmonitor)...")
            device_monitor = DeviceConnectionMonitor(send_alerts=True)
            
            if device_monitor.start_monitoring():
                print("[PrivAware] Device Connection Monitor is now active.")
                print("[PrivAware] Alerts will be sent for new USB device connections.")
                print("[PrivAware] Press Ctrl+C to stop.")
                try:
                    # Keep the main thread alive while the monitor runs in the background
                    while True:
                        time.sleep(1)
                except KeyboardInterrupt:
                    print("\n[PrivAware] Received interrupt signal.")
                finally:
                    device_monitor.stop_monitoring()
                    print("[PrivAware] Device Connection Monitor stopped.")
            else:
                print("[PrivAware] Failed to start Device Connection Monitor.")
                
        except ImportError as e:
            print(f"[PrivAware] Error: {e}")
            print("[PrivAware] Ensure 'pyudev' is installed: pip install pyudev")
        except Exception as e:
            print(f"[PrivAware] Unexpected error starting device monitor: {e}")
        
        # Exit after monitoring is stopped or failed to start
        return # Add this return    

    # Update this condition to include new arguments:
    if not any([args.audit, args.monitor, args.realtime_monitor, args.logs, args.filewatch, 
                args.realtime_watch, args.servicecheck, args.test_alert, args.check_config,
                args.snapshot_list, args.snapshot_show, args.setup, args.dmonitor]):
        parser.print_help()

if __name__ == "__main__":
    main()
