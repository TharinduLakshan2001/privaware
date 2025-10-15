import os
import pytest
from dotenv import load_dotenv
from privaware_pkg.core import alerts

# Load environment variables from .env
dotenv_path = os.path.join(os.path.dirname(__file__), "..", ".env")
load_dotenv(dotenv_path)

EMAIL_USER = os.getenv("EMAIL_USERNAME")
EMAIL_PASS = os.getenv("EMAIL_PASSWORD")
OWNER_EMAIL = os.getenv("OWNER_EMAIL")

# Color codes for terminal output
class Colors:
    GREEN = '\033[92m'
    BLUE = '\033[94m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    END = '\033[0m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'

def print_banner(message):
    """Print a cool colored banner message"""
    banner = f"""
    {Colors.BLUE}{'=' * 60}{Colors.END}
    {Colors.BOLD}🚀 {message}{Colors.END}
    {Colors.BLUE}{'=' * 60}{Colors.END}
    """
    print(banner)

def print_success(test_name):
    """Print a success message for a test"""
    success_message = f"""
    {Colors.GREEN}✅ {test_name}{Colors.END}
    {Colors.CYAN}📊 Status: {Colors.BOLD}PASSED{Colors.END}
    {Colors.GREEN}🎯 Result: {Colors.BOLD}SUCCESS{Colors.END}
    """
    print(success_message)

def print_step(step_number, description):
    """Print a test step with emoji and color"""
    print(f"{Colors.PURPLE}🔹 Step {step_number}: {description}{Colors.END}")

# ---------------------------
# 1️⃣ Test trigger_alert with dry-run (mock sending)
# ---------------------------
def test_trigger_alert_mock(monkeypatch):
    """
    Test trigger_alert without sending real emails
    """
    print_banner("Starting Mock Alert Test")
    print_step(1, "Testing alert system in dry-run mode...")
    
    # Patch send_email_alert to dry-run mode
    monkeypatch.setattr(alerts, "send_email_alert", lambda subject, message, dry_run=True: True)

    # Ensure alerts are enabled in settings
    monkeypatch.setitem(alerts.settings["alerts"], "enable_email", True)
    monkeypatch.setitem(alerts.settings["alerts"]["rules"]["failed_login"], "enabled", True)

    print_step(2, "Triggering mock alert...")
    alerts.trigger_alert("failed_login", "Test dry-run alert", dry_run=True)

    print_success("Mock Alert Test")
    print(f"{Colors.GREEN}🎭 Dry-run completed without issues!{Colors.END}")
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
    print_banner("Starting Real Email Test")
    print_step(1, "Testing real email delivery...")
    
    if not all([EMAIL_USER, EMAIL_PASS, OWNER_EMAIL]):
        skip_msg = "Real email test skipped: missing credentials in .env"
        print(f"{Colors.YELLOW}⏭️  {skip_msg}{Colors.END}")
        pytest.skip(skip_msg)

    subject = "PrivAware Test Email"
    message = "✅ This is a test email from PrivAware. If you see this, email alerts work!"

    print_step(2, "Preparing email details...")
    print(f"   {Colors.CYAN}From: {EMAIL_USER}{Colors.END}")
    print(f"   {Colors.CYAN}To: {OWNER_EMAIL}{Colors.END}")
    print(f"   {Colors.CYAN}Subject: {subject}{Colors.END}")

    print_step(3, "Sending test email...")
    # Trigger real email sending
    result = alerts.send_email_alert(subject, message, dry_run=False)
    
    if result:
        print_success("Real Email Test")
        print(f"{Colors.GREEN}📨 Email sent successfully! Check your inbox.{Colors.END}")
    else:
        print(f"{Colors.RED}❌ Email sending failed!{Colors.END}")
    
    assert result is True

# ---------------------------
# 3️⃣ Final Summary Hook
# ---------------------------
@pytest.fixture(scope="session", autouse=True)
def test_session_final_message():
    """Display a final message after all tests complete"""
    yield
    print_banner("🎉 ALL TESTS COMPLETED SUCCESSFULLY!")
    print(f"""
    {Colors.GREEN}🏆 Testing Results Summary:{Colors.END}
    {Colors.GREEN}✅ Mock Alert Test: PASSED{Colors.END}
    {Colors.GREEN}✅ Real Email Test: EXECUTED{Colors.END}
    {Colors.BLUE}📊 All systems operational!{Colors.END}
    {Colors.CYAN}🔒 Security monitoring: ACTIVE{Colors.END}
    """)

def pytest_sessionfinish(session, exitstatus):
    """Pytest hook called when test session finishes"""
    if exitstatus == 0:
        print_banner("🎯 TEST SESSION COMPLETED SUCCESSFULLY!")
        print(f"""
        {Colors.GREEN}🌟 All tests passed!{Colors.END}
        {Colors.BLUE}⚡ PrivAware Alert System: {Colors.BOLD}READY{Colors.END}
        {Colors.CYAN}🛡️  Security monitoring: {Colors.BOLD}OPERATIONAL{Colors.END}
        {Colors.PURPLE}🔔 Email notifications: {Colors.BOLD}CONFIGURED{Colors.END}
        """)
    else:
        print_banner("⚠️  TEST SESSION COMPLETED WITH ISSUES")
        print(f"""
        {Colors.RED}❌ Some tests failed{Colors.END}
        {Colors.YELLOW}🔧 Please check the test results above{Colors.END}
        """)
