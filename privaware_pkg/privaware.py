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

def run_monitor():
    """Check system health (CPU, memory, disk)."""
    from rich.console import Console
    from rich.table import Table
    
    console = Console()
    monitor = SystemMonitor()
    metrics = monitor.get_system_metrics()
    
    table = Table(title="[bold blue]System Health Monitor[/bold blue]")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    table.add_column("Status", style="yellow")
    
    for key, value in metrics.items():
        if isinstance(value, dict):
            status = value.get('status', 'OK')
            val = value.get('value', 'N/A')
            table.add_row(key, str(val), status)
        else:
            table.add_row(key, str(value), "OK")
    
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
    """Check status of critical services."""
    from rich.console import Console
    from rich.table import Table
    
    console = Console()
    service_checker = ServiceChecker()
    services = ["sshd", "dnsmasq", "nginx"]  # Default services
    
    console.print("[bold blue]Checking service status...[/bold blue]")
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
    parser = argparse.ArgumentParser(
        description="PrivAware CLI - Linux Privacy & Security Toolkit",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('--setup', action='store_true', help='Run initial setup and configuration')
    parser.add_argument('--audit', action='store_true', help='Run system audit checks')
    parser.add_argument('--monitor', action='store_true', help='Check system health (CPU, memory, disk)')
    parser.add_argument('--logs', action='store_true', help='Parse logs for suspicious activity')
    parser.add_argument('--filewatch', action='store_true', help='Monitor sensitive files for changes')
    parser.add_argument('--realtime-watch', action='store_true', help='Real-time file system monitoring with alerts')
    parser.add_argument('--servicecheck', action='store_true', help='Check status of critical services')
    parser.add_argument('--test-alert', action='store_true', help='Send a test alert email')
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

    # Run selected modules
    if args.audit:
        run_audit()
    
    if args.monitor:
        run_monitor()
        
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
        
    # If no arguments provided, show help
    if not any([args.audit, args.monitor, args.logs, args.filewatch, 
                args.realtime_watch, args.servicecheck, args.test_alert]):
        parser.print_help()

if __name__ == "__main__":
    main()
