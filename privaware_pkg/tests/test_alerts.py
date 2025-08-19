import os
import pytest
from dotenv import load_dotenv
from privaware_pkg.core import alerts

# Load .env secrets
load_dotenv()

EMAIL_USER = os.getenv("EMAIL_USERNAME")
EMAIL_PASS = os.getenv("EMAIL_PASSWORD")
OWNER_EMAIL = os.getenv("OWNER_EMAIL")


# ---------------------------
# 1️⃣ Test trigger_alert with mock email
# ---------------------------
def test_trigger_alert_mock(monkeypatch):
    """Test trigger_alert without sending real emails"""

    # Disable actual sending
    monkeypatch.setattr(alerts, "send_email_alert", lambda subject, msg: True)

    # Make sure alerts are enabled in settings
    monkeypatch.setitem(alerts.settings["alerts"], "enable_email", True)
    monkeypatch.setitem(alerts.settings["alerts"]["rules"]["failed_login"], "enabled", True)

    # Trigger alert
    alerts.trigger_alert("failed_login", "Test user failed login")

    # If no exceptions occur, test passes
    assert True


# ---------------------------
# 2️⃣ Test sending a real email
# ---------------------------
@pytest.mark.real_email
def test_send_real_email():
    """
    Send a real test email to OWNER_EMAIL using Gmail SMTP.
    Ensure your .env has correct EMAIL_USERNAME and EMAIL_PASSWORD (App Password).
    """
    subject = "PrivAware Test Email"
    message = "✅ This is a test email from PrivAware. If you see this, email alerts work!"

    result = alerts.send_email_alert(subject, message)
    assert result is True
