import os
import pytest
from dotenv import load_dotenv
from privaware_pkg.core import alerts
#from core import alerts

# Load environment variables from .env
dotenv_path = os.path.join(os.path.dirname(__file__), "..", ".env")
load_dotenv(dotenv_path)

EMAIL_USER = os.getenv("EMAIL_USERNAME")
EMAIL_PASS = os.getenv("EMAIL_PASSWORD")
OWNER_EMAIL = os.getenv("OWNER_EMAIL")

# ---------------------------
# 1️⃣ Test trigger_alert with dry-run (mock sending)
# ---------------------------
def test_trigger_alert_mock(monkeypatch):
    """
    Test trigger_alert without sending real emails
    """
    # Patch send_email_alert to dry-run mode
    monkeypatch.setattr(alerts, "send_email_alert", lambda subject, message, dry_run=True: True)

    # Ensure alerts are enabled in settings
    monkeypatch.setitem(alerts.settings["alerts"], "enable_email", True)
    monkeypatch.setitem(alerts.settings["alerts"]["rules"]["failed_login"], "enabled", True)

    alerts.trigger_alert("failed_login", "Test dry-run alert", dry_run=True)

    # If no exceptions occur, test passes
    assert True

# ---------------------------
# 2️⃣ Test sending a real email
# ---------------------------
@pytest.mark.real_email
def test_send_real_email():
    """
    Send a real test email to OWNER_EMAIL using Gmail SMTP.
    Make sure your .env has correct EMAIL_USERNAME and EMAIL_PASSWORD (App Password).
    """
    if not all([EMAIL_USER, EMAIL_PASS, OWNER_EMAIL]):
        pytest.skip("Real email test skipped: missing credentials in .env")

    subject = "PrivAware Test Email"
    message = "✅ This is a test email from PrivAware. If you see this, email alerts work!"

    # Trigger real email sending
    result = alerts.send_email_alert(subject, message, dry_run=False)
    assert result is True
