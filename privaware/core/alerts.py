import os
import smtplib
import json
import logging
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()

# Load settings.json
SETTINGS_PATH = os.path.join(os.path.dirname(__file__), "..", "config", "settings.json")
with open(SETTINGS_PATH, "r") as f:
    settings = json.load(f)

# Logging setup
log_file = settings["logging"]["log_file"]
log_level = getattr(logging, settings["logging"]["log_level"].upper(), logging.INFO)
logging.basicConfig(filename=log_file, level=log_level,
                    format="%(asctime)s [%(levelname)s] %(message)s")

# Secrets from .env
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")  # Gmail App Password
EMAIL_USER = os.getenv("EMAIL_USER")          # your Gmail address


def send_email_alert(subject: str, message: str):
    """Send an email alert if alerts are enabled in settings.json"""

    if not settings["alerts"]["enable_email"]:
        logging.info("Email alerts are disabled. Skipping.")
        return False

    try:
        sender = settings["alerts"]["email_from"]
        recipient = settings["alerts"]["email_to"]

        # Create the email
        msg = MIMEMultipart()
        msg["From"] = sender
        msg["To"] = recipient
        msg["Subject"] = subject
        msg.attach(MIMEText(message, "plain"))

        # Connect to Gmail
        server = smtplib.SMTP(settings["alerts"]["smtp_server"], settings["alerts"]["smtp_port"])
        server.starttls()
        server.login(EMAIL_USER, EMAIL_PASSWORD)
        server.sendmail(sender, recipient, msg.as_string())
        server.quit()

        logging.info(f"Alert sent: {subject}")
        return True

    except Exception as e:
        logging.error(f"Failed to send alert: {e}")
        return False


def trigger_alert(event_type: str, details: str = ""):
    """
    Trigger an alert for a given event type (failed_login, root_access, etc.)
    Reads rules from settings.json.
    """

    rules = settings["alerts"]["rules"]

    if event_type not in rules:
        logging.warning(f"Unknown event type: {event_type}")
        return

    if not rules[event_type]["enabled"]:
        logging.info(f"Alert for '{event_type}' is disabled.")
        return

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    subject = f"[PrivAware] Security Alert - {event_type.replace('_', ' ').title()}"
    message = f"Event: {event_type}\nTime: {now}\nDetails: {details}"

    send_email_alert(subject, message)
