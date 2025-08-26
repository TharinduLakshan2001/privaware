
"""
Alerts module: Handles sending alerts based on triggered rules.
"""
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv(os.path.join(os.path.dirname(__file__), '..', '.env'))

EMAIL_FROM = os.getenv('EMAIL_USERNAME')
EMAIL_PASS = os.getenv('EMAIL_PASSWORD')
EMAIL_TO = os.getenv('OWNER_EMAIL')

class AlertSender:
	def __init__(self, email_from=EMAIL_FROM, email_pass=EMAIL_PASS, email_to=EMAIL_TO):
		self.email_from = email_from
		self.email_pass = email_pass
		self.email_to = email_to

	def send_alert(self, subject, message):
		if not all([self.email_from, self.email_pass, self.email_to]):
			print("[ALERT] Email credentials not set. Cannot send alert.")
			return False
		try:
			msg = MIMEMultipart()
			msg['From'] = self.email_from
			msg['To'] = self.email_to
			msg['Subject'] = subject
			msg.attach(MIMEText(message, 'plain'))

			with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
				server.login(self.email_from, self.email_pass)
				server.sendmail(self.email_from, self.email_to, msg.as_string())
			print(f"[ALERT] Email sent to {self.email_to}")
			return True
		except Exception as e:
			print(f"[ALERT] Failed to send email: {e}")
			return False

def send_test_alert():
	sender = AlertSender()
	return sender.send_alert("PrivAware Test Alert", "This is a test alert from PrivAware.")

if __name__ == "__main__":
	send_test_alert()
