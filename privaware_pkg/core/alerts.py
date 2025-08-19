import os
import smtplib
import json
import logging
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

# --------------------------
# Load environment variables
# --------------------------
dotenv_path = os.path.join(os.path.dirname(__file__), "..", ".env")
load_dotenv(dotenv_path)

EMAIL_USER = os.getenv("EMAIL_USERNAME")  # Gmail address
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")  # Gmail App Password
OWNER_EMAIL = os.getenv("OWNER_EMAIL")  # Recipient

# --------------------------
# Load settings.json
# --------------------------
SETTINGS_PATH = os.path.join(os.path.dirname(__file__), "..", "config", "settings.json")
with open(SETTINGS_PATH, "r") as f:
    settings = json.load(f)

# --------------------------
# Logging setup
# --------------------------
log_file = settings["logging"].get("log_file", "privaware.log")
log_level = getattr(logging, settings["logging"].get("log_level", "INFO").upper(), logging.INFO)
logging.basicConfig(
    filename=log_file,
    level=log_level,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

# --------------------------
# Email sending function
# --------------------------
def send_email_alert(subject: str, message: str, dry_run: bool = False) -> bool:
    """
    Send an email alert if enabled in settings.
    Set dry_run=True to skip real sending (useful for pytest).
    """
    if not settings["alerts"].get("enable_email", False):
        logging.info("Email alerts are disabled. Skipping.")
        return False

    try:
        sender = EMAIL_USER
        recipient = OWNER_EMAIL

        msg = MIMEMultipart()
        msg["From"] = sender
        msg["To"] = recipient
        msg["Subject"] = subject
        msg.attach(MIMEText(message, "plain"))

        if dry_run:
            logging.info(f"[DRY RUN] Email prepared for {recipient}: {subject}")
            return True

        # Connect and send via Gmail SMTP
        server = smtplib.SMTP(settings["alerts"]["smtp_server"], settings["alerts"]["smtp_port"])
        server.starttls()
        server.login(EMAIL_USER, EMAIL_PASSWORD)
        server.sendmail(sender, recipient, msg.as_string())
        server.quit()

        logging.info(f"Alert sent to {recipient}: {subject}")
        return True

    except Exception as e:
        logging.error(f"Failed to send alert: {e}")
        return False

# --------------------------
# Trigger alerts by event type
# --------------------------
def trigger_alert(event_type: str, details: str = "", dry_run: bool = False):
    """
    Trigger an alert based on event_type.
    Reads rules from settings.json.
    """
    rules = settings["alerts"].get("rules", {})

    if event_type not in rules:
        logging.warning(f"Unknown event type: {event_type}")
        return

    if not rules[event_type].get("enabled", False):
        logging.info(f"Alert for '{event_type}' is disabled.")
        return

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    subject = f"[PrivAware] Security Alert - {event_type.replace('_', ' ').title()}"
    message = f"Event: {event_type}\nTime: {now}\nDetails: {details}"

    send_email_alert(subject, message, dry_run=dry_run)
