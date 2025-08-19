import os
from pathlib import Path
from getpass import getpass

def run_setup():
    print("=== PrivAware Setup ===")

    # Ask for user inputs
    email_username = input("Enter your Gmail address (alerts will be sent from this): ").strip()
    email_password = getpass("Enter your Gmail App Password: ").strip()
    owner_email = input("Enter the owner email (alert recipient): ").strip()

    # Create .env file content
    env_content = f"""# PrivAware environment settings
EMAIL_USERNAME={email_username}
EMAIL_PASSWORD={email_password}
OWNER_EMAIL={owner_email}
"""

    # Save to .env in project root
    env_path = Path(__file__).resolve().parent.parent / ".env"

    if env_path.exists():
        confirm = input(f"{env_path} already exists. Overwrite? (y/n): ").strip().lower()
        if confirm != "y":
            print("❌ Setup cancelled, keeping existing .env file.")
            return

    with open(env_path, "w") as f:
        f.write(env_content)

    print(f"✅ Setup complete. Credentials saved to {env_path}")
    print("⚠️ Make sure `.env` is in your .gitignore so secrets are not pushed to GitHub!")

if __name__ == "__main__":
    run_setup()
