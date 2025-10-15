#!/usr/bin/env python3
"""
PrivAware Setup Script: Installs all Python and system dependencies.
Also sets up the package for command-line usage.
"""
import os
import sys
import subprocess
import getpass
from setuptools import setup, find_packages

REQUIREMENTS_FILE = "requirements.txt"

# System packages needed (Debian/Ubuntu/Kali)
SYSTEM_PACKAGES = [
    "python3-pip", "python3-venv", "iptables", "net-tools", "procps"
]

def check_root():
    """Check if running as root for system package installation"""
    return os.geteuid() == 0

def install_system_packages():
    print("[PrivAware] 🔧 Installing system packages...")
    try:
        # Update package list
        subprocess.check_call(["sudo", "apt-get", "update"])
        
        # Install system packages
        subprocess.check_call(["sudo", "apt-get", "install", "-y"] + SYSTEM_PACKAGES)
        print("[PrivAware] ✅ System packages installed successfully!")
    except subprocess.CalledProcessError as e:
        print(f"[PrivAware] ⚠️  Warning: System package installation failed: {e}")
        print("[PrivAware] 💡 Continuing with Python package installation...")

def read_requirements():
    """Read requirements from file"""
    try:
        with open(REQUIREMENTS_FILE, 'r') as f:
            requirements = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        return requirements
    except FileNotFoundError:
        print(f"[PrivAware] ⚠️  Warning: {REQUIREMENTS_FILE} not found, using default requirements")
        return [
            'psutil>=7.0.0',
            'watchdog>=6.0.0', 
            'rich>=14.1.0',
            'python-dotenv>=1.1.1'
        ]

def install_python_packages():
    print("[PrivAware] 🐍 Installing Python dependencies...")
    try:
        # Upgrade pip first
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", "pip"])
        
        # Install requirements
        requirements = read_requirements()
        for req in requirements:
            print(f"[PrivAware] 📦 Installing {req}...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", req])
        
        print("[PrivAware] ✅ Python packages installed successfully!")
    except subprocess.CalledProcessError as e:
        print(f"[PrivAware] ❌ Error: Python package installation failed: {e}")
        sys.exit(1)

def collect_email_config():
    """Collect email configuration from user"""
    print("\n📧 Email Configuration")
    print("=" * 30)
    print("PrivAware needs email configuration to send security alerts.")
    print("You can use Gmail with App Passwords for this.")
    
    # Get server email configuration
    print("\n🔐 Alert Server Configuration:")
    print("This is the email account that will SEND alerts.")
    server_email = input("📧 Server email address (e.g., your@gmail.com): ").strip()
    
    if not server_email:
        print("[PrivAware] ⚠️  Skipping server configuration")
        return None, None, None
    
    # Securely get password (hidden input)
    server_password = getpass.getpass("🔑 App password (hidden): ").strip()
    
    # Get owner email (recipient)
    print("\n📬 Alert Recipient Configuration:")
    print("This is where you want to RECEIVE alerts.")
    owner_email = input("📧 Your email address to receive alerts: ").strip()
    
    if not owner_email:
        print("[PrivAware] ⚠️  No recipient email provided")
        return server_email, server_password, None
    
    return server_email, server_password, owner_email

def write_env_file(server_email, server_password, owner_email):
    """Create .env file with email configuration"""
    env_path = os.path.join(os.path.dirname(__file__), ".env")
    
    # Read existing .env file if it exists
    existing_config = {}
    if os.path.exists(env_path):
        with open(env_path, 'r') as f:
            for line in f:
                if '=' in line and not line.strip().startswith('#'):
                    key, value = line.strip().split('=', 1)
                    existing_config[key] = value
    
    # Update with new values
    existing_config['EMAIL_USERNAME'] = server_email or existing_config.get('EMAIL_USERNAME', '')
    existing_config['EMAIL_PASSWORD'] = server_password or existing_config.get('EMAIL_PASSWORD', '')
    existing_config['OWNER_EMAIL'] = owner_email or existing_config.get('OWNER_EMAIL', '')
    
    # Write updated config
    with open(env_path, "w") as f:
        f.write("# PrivAware environment settings\n")
        f.write("# This file contains sensitive information - keep it secure!\n")
        f.write(f"EMAIL_USERNAME={existing_config['EMAIL_USERNAME']}\n")
        f.write(f"EMAIL_PASSWORD={existing_config['EMAIL_PASSWORD']}\n")
        f.write(f"OWNER_EMAIL={existing_config['OWNER_EMAIL']}\n")
    
    print(f"[PrivAware] ✅ Configuration file updated at {env_path}")
    return env_path

def setup_interactive():
    """Interactive setup for new users"""
    print("🔐 Welcome to PrivAware Setup!")
    print("🛡️  Linux Privacy & Security Toolkit")
    print("=" * 50)
    
    # Install system packages (requires sudo)
    print("\n🔧 Step 1: Installing system dependencies...")
    install_system_packages()
    
    # Install Python packages
    print("\n🐍 Step 2: Installing Python dependencies...")
    install_python_packages()
    
    # Configure email alerts
    print("\n📧 Step 3: Configure email alerts")
    server_email, server_password, owner_email = collect_email_config()
    
    if server_email or owner_email:
        env_path = write_env_file(server_email, server_password, owner_email)
        print(f"\n📄 Configuration saved to: {env_path}")
    else:
        print("[PrivAware] ℹ️  Email configuration skipped")
    
    print("\n✅ Setup complete!")
    print("\n🚀 You can now use PrivAware!")
    print("   Run: python -m privaware_pkg.privaware --help")
    print("   After installation: privaware --help")

# Setup configuration for package distribution
setup(
    name="privaware",
    version="1.0.0",
    description="Linux privacy and security auditing and monitoring tool",
    long_description=open("README.md").read() if os.path.exists("README.md") else "PrivAware - Linux Security Toolkit",
    long_description_content_type="text/markdown",
    author="Security Researcher",
    packages=find_packages(),
    install_requires=read_requirements(),
    entry_points={
        'console_scripts': [
            'privaware=privaware_pkg.privaware:main',
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Topic :: Security",
    ],
    python_requires=">=3.6",
)

# Handle command line arguments
if __name__ == "__main__":
    if len(sys.argv) == 1:
        # No arguments - run interactive setup
        setup_interactive()
    elif "--help" in sys.argv or "-h" in sys.argv:
        print("PrivAware Setup Options:")
        print("  (no args)    : Run interactive setup")
        print("  --help, -h   : Show this help")
        print("\nAfter setup, install the package with: pip install -e .")
    else:
        # Let setuptools handle package installation
        pass
