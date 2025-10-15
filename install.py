#!/usr/bin/env python3
"""
PrivAware Complete Installation System
Combines setup and installation into one unified process.
"""
import os
import sys
import subprocess
import getpass
import shutil
import platform
from pathlib import Path
import time

class Colors:
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

def display_banner():
    banner = f"""
{Colors.CYAN}{Colors.BOLD}
██████╗ ██████╗ ██╗██╗   ██╗ █████╗ ██╗    ██╗ █████╗ ██████╗ ███████╗
██╔══██╗██╔══██╗██║██║   ██║██╔══██╗██║    ██║██╔══██╗██╔══██╗██╔════╝
██████╔╝██████╔╝██║██║   ██║███████║██║ █╗ ██║███████║██████╔╝█████╗  
██╔═══╝ ██╔══██╗██║╚██╗ ██╔╝██╔══██║██║███╗██║██╔══██║██╔══██╗██╔══╝  
██║     ██║  ██║██║ ╚████╔╝ ██║  ██║╚███╔███╔╝██║  ██║██║  ██║███████╗
╚═╝     ╚═╝  ╚═╝╚═╝  ╚═══╝  ╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝
{Colors.RESET}
{Colors.BLUE}═══════════════════════════════════════════════════════════════════════
    PrivAware - Linux Privacy & Security Toolkit
    Complete Installation System | Version 1.0.0
═══════════════════════════════════════════════════════════════════════{Colors.RESET}
"""
    print(banner)

def print_status(message, status="info"):
    """Print status messages with colors"""
    status_colors = {
        "info": Colors.BLUE,
        "success": Colors.GREEN,
        "warning": Colors.YELLOW,
        "error": Colors.RED,
        "progress": Colors.CYAN
    }
    color = status_colors.get(status, Colors.BLUE)
    print(f"{color}[PrivAware] {message}{Colors.RESET}")

def run_command(cmd, description="", capture_output=True, check=True):
    """Run a command with progress indication"""
    if description:
        print_status(f"{description}...", "progress")
    
    try:
        if capture_output:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, check=check
            )
            if check and result.returncode != 0:
                print_status(f"Command failed: {cmd}", "error")
                print_status(f"Error: {result.stderr}", "error")
                return False, result.stdout, result.stderr
            return True, result.stdout, result.stderr
        else:
            result = subprocess.run(cmd, shell=True, check=check)
            return result.returncode == 0, "", ""
    except subprocess.CalledProcessError as e:
        print_status(f"Command failed: {cmd}", "error")
        print_status(f"Error: {e}", "error")
        return False, "", str(e)
    except Exception as e:
        print_status(f"Unexpected error: {e}", "error")
        return False, "", str(e)

def check_dependencies():
    """Check if required system dependencies are available"""
    print_status("Checking system dependencies...", "info")
    
    dependencies = {
        'python3': 'which python3',
        'pip': 'which pip3',
        'git': 'which git',
        'sudo': 'which sudo'
    }
    
    missing = []
    for name, cmd in dependencies.items():
        success, _, _ = run_command(cmd, capture_output=True, check=False)
        if not success:
            missing.append(name)
    
    if missing:
        print_status(f"Missing dependencies: {', '.join(missing)}", "warning")
        return False
    else:
        print_status("All system dependencies found", "success")
        return True

def create_virtual_environment():
    """Create and set up virtual environment"""
    print_status("Setting up virtual environment...", "info")
    
    # Clean up any corrupted files first
    venv_path = Path("venv")
    if venv_path.exists():
        print_status("Cleaning existing virtual environment...", "info")
        import shutil
        shutil.rmtree(venv_path)
    
    success, _, stderr = run_command("python3 -m venv venv", "Creating virtual environment")
    if not success:
        print_status(f"Failed to create virtual environment: {stderr}", "error")
        return False
    
    # Activate virtual environment for subsequent commands
    venv_python = str(venv_path / "bin" / "python")
    venv_pip = str(venv_path / "bin" / "pip")
    
    # Upgrade pip
    success, _, _ = run_command(f"{venv_pip} install --upgrade pip", "Upgrading pip")
    if not success:
        print_status("Warning: Failed to upgrade pip", "warning")
    
    print_status("Virtual environment created successfully", "success")
    return True

def install_python_dependencies():
    """Install Python dependencies from requirements.txt"""
    print_status("Installing Python dependencies...", "info")
    
    if not os.path.exists("privaware_pkg/requirements.txt"):
        print_status("requirements.txt not found, installing basic dependencies", "warning")
        basic_deps = ["psutil", "watchdog", "rich", "python-dotenv", "click"]
        venv_pip = "venv/bin/pip"
        
        for dep in basic_deps:
            success, _, _ = run_command(f"{venv_pip} install {dep}", f"Installing {dep}")
            if not success:
                print_status(f"Failed to install {dep}", "error")
                return False
    else:
        venv_pip = "venv/bin/pip"
        success, _, stderr = run_command(
            f"{venv_pip} install -r privaware_pkg/requirements.txt", 
            "Installing dependencies from requirements.txt"
        )
        if not success:
            print_status(f"Failed to install dependencies: {stderr}", "error")
            return False
    
    print_status("Python dependencies installed successfully", "success")
    return True

def install_privaware_package():
    """Install PrivAware package in development mode"""
    print_status("Installing PrivAware package...", "info")
    
    venv_pip = "venv/bin/pip"
    success, _, stderr = run_command(
        f"{venv_pip} install -e .", 
        "Installing PrivAware in development mode"
    )
    
    if not success:
        print_status(f"Failed to install package: {stderr}", "error")
        return False
    
    print_status("PrivAware package installed successfully", "success")
    return True

def setup_email_configuration():
    """Interactive email configuration for both locations"""
    print_status("Setting up email configuration...", "info")
    
    print(f"\n{Colors.YELLOW}📧 Email Configuration{Colors.RESET}")
    print("=" * 50)
    print("PrivAware needs email configuration to send security alerts.")
    print("You can use Gmail with App Passwords for this.")
    
    # Get server email configuration
    print(f"\n{Colors.CYAN}🔐 Alert Server Configuration:{Colors.RESET}")
    print("This is the email account that will SEND alerts.")
    server_email = input("📧 Server email address (e.g., your@gmail.com): ").strip()
    
    if not server_email:
        print_status("Skipping email configuration", "warning")
        return True
    
    # Securely get password (hidden input)
    server_password = getpass.getpass("🔑 App password (hidden): ").strip()
    
    # Get owner email (recipient)
    print(f"\n{Colors.CYAN}📬 Alert Recipient Configuration:{Colors.RESET}")
    print("This is where you want to RECEIVE alerts.")
    owner_email = input("📧 Your email address to receive alerts: ").strip()
    
    if not owner_email:
        owner_email = server_email  # Use same email if no recipient specified
    
    # Create .env content
    env_content = f"""# PrivAware environment settings
# This file contains sensitive information - keep it secure!
EMAIL_USERNAME={server_email}
EMAIL_PASSWORD={server_password}
OWNER_EMAIL={owner_email}
"""
    
    # Write to BOTH locations to ensure consistency
    locations = [".env", "privaware_pkg/.env"]
    
    for location in locations:
        try:
            with open(location, "w") as f:
                f.write(env_content)
            print_status(f"Configuration saved to: {location}", "success")
        except Exception as e:
            print_status(f"Failed to write {location}: {e}", "error")
            if location == ".env":  # If main .env fails, try to create it in package
                continue
            else:
                return False
    
    print_status("Email configuration completed successfully", "success")
    return True

def create_system_wide_command():
    """Create system-wide command for easy access"""
    print_status("Creating system-wide command...", "info")
    
    # Create the launcher script
    launcher_script = f"""#!/bin/bash
# PrivAware system launcher
cd {os.getcwd()} 2>/dev/null || cd $(pwd)
source venv/bin/activate 2>/dev/null || true
python3 -m privaware_pkg.privaware "$@"
"""
    
    # Write to system location
    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.sh') as f:
        f.write(launcher_script)
        temp_script = f.name
    
    try:
        # Move to system location with sudo
        success, _, stderr = run_command(
            f"sudo mv {temp_script} /usr/local/bin/privaware && sudo chmod +x /usr/local/bin/privaware",
            "Installing system-wide command"
        )
        
        if success:
            print_status("System-wide command installed successfully", "success")
            return True
        else:
            print_status(f"Failed to install system command: {stderr}", "warning")
            print_status("You can still run PrivAware with: python3 -m privaware_pkg.privaware", "info")
            return True  # Don't fail the entire installation for this
    except Exception as e:
        print_status(f"Error creating system command: {e}", "warning")
        print_status("You can still run PrivAware with: python3 -m privaware_pkg.privaware", "info")
        return True

def setup_system_service():
    """Setup systemd service for background monitoring"""
    print_status("Setting up system service (optional)...", "info")
    
    service_content = f"""[Unit]
Description=PrivAware Security Monitoring Service
After=network.target

[Service]
Type=simple
User={getpass.getuser()}
WorkingDirectory={os.getcwd()}
Environment=PATH={os.getcwd()}/venv/bin
ExecStart={os.getcwd()}/venv/bin/python3 -m privaware_pkg.privaware --check-config --interval 300
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
"""
    
    # Write service file
    service_path = "/tmp/privaware_agent.service"
    with open(service_path, "w") as f:
        f.write(service_content)
    
    # Try to install service (may require sudo)
    success, _, _ = run_command(
        f"sudo cp {service_path} /etc/systemd/system/ && sudo systemctl daemon-reload",
        "Setting up systemd service",
        check=False  # Don't fail if user doesn't have sudo
    )
    
    if success:
        print_status("System service configured successfully", "success")
        print_status("Enable with: sudo systemctl enable privaware_agent", "info")
        print_status("Start with: sudo systemctl start privaware_agent", "info")
    else:
        print_status("System service setup skipped (requires sudo)", "warning")
    
    # Clean up temp file
    os.unlink(service_path)
    return True

def cleanup_corrupted_files():
    """Clean up any corrupted distribution files"""
    print_status("Cleaning up corrupted files...", "info")
    
    # Remove corrupted distribution files
    venv_path = Path("venv/lib/python3.*/site-packages")
    for pattern in ["~*", "*.dist-info", "*.egg-info"]:
        for path in venv_path.glob(pattern):
            try:
                if path.is_dir():
                    shutil.rmtree(path)
                else:
                    path.unlink()
            except:
                pass  # Silently ignore cleanup errors
    
    print_status("Cleanup completed", "success")

def run_privaware_help():
    """Test the installation by running help command"""
    print_status("Testing installation...", "info")
    
    success, stdout, stderr = run_command(
        "python3 -m privaware_pkg.privaware --help",
        "Testing PrivAware command",
        check=False
    )
    
    if success:
        print_status("Installation test successful!", "success")
        print(f"\n{Colors.GREEN}🎉 PrivAware is ready to use!{Colors.RESET}")
        print(f"\n{Colors.CYAN}Available commands:{Colors.RESET}")
        print("   privaware --help              # Show help")
        print("   privaware --audit             # Security audit")
        print("   privaware --monitor           # System monitoring")
        print("   privaware --check-config      # Privacy checks")
        print("   privaware --realtime-watch    # File monitoring")
        return True
    else:
        print_status(f"Installation test failed: {stderr}", "error")
        return False

def main():
    """Main installation process"""
    display_banner()
    
    print_status("Starting PrivAware Complete Installation", "info")
    print(f"{Colors.CYAN}This will install PrivAware with all dependencies and configurations{Colors.RESET}")
    print()
    
    # Ask for confirmation
    response = input(f"{Colors.YELLOW}Continue with installation? (y/N): {Colors.RESET}").strip().lower()
    if response not in ['y', 'yes']:
        print_status("Installation cancelled", "info")
        return
    
    print()
    
    # Step 1: Check dependencies
    if not check_dependencies():
        print_status("Dependency check failed", "error")
        return
    
    # Step 2: Clean up any corrupted files
    cleanup_corrupted_files()
    
    # Step 3: Create virtual environment
    if not create_virtual_environment():
        print_status("Virtual environment setup failed", "error")
        return
    
    # Step 4: Install Python dependencies
    if not install_python_dependencies():
        print_status("Python dependencies installation failed", "error")
        return
    
    # Step 5: Install PrivAware package
    if not install_privaware_package():
        print_status("Package installation failed", "error")
        return
    
    # Step 6: Email configuration (writes to both locations)
    setup_email_configuration()
    
    # Step 7: Create system-wide command
    create_system_wide_command()
    
    # Step 8: Optional system service
    setup_system_service()
    
    # Step 9: Test installation
    run_privaware_help()
    
    print()
    print_status("🎉 PrivAware Complete Installation Finished! 🎉", "success")
    print(f"\n{Colors.GREEN}🚀 You can now use PrivAware!{Colors.RESET}")
    print(f"\n{Colors.CYAN}Quick start commands:{Colors.RESET}")
    print("   privaware --help              # Show all options")
    print("   privaware --audit             # Run security audit")
    print("   privaware --realtime-watch    # Start file monitoring")
    print("   privaware --check-config      # Privacy configuration check")
    print()
    print_status("Thank you for using PrivAware - Your Linux Security Companion!", "info")

if __name__ == "__main__":
    main()
