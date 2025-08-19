#!/usr/bin/env python3
import smtplib
import time
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import getpass

class EmailSender:
    def __init__(self):
        self.sender_email = "your_email@gmail.com"  # CHANGE THIS
        self.reender_email = "tharinduhero500@gmail.com"
        self.subject = "Uba Hukapan Huthto"
        self.message = "Uba Hukapan Huthto"
        
        # Gmail SMTP settings
        self.smtp_server = "smtp.gmail.com"
        self.smtp_port = 587
        
    def setup_credentials(self):
        """Get email credentials securely"""
        print("Please enter your Gmail credentials:")
        self.sender_email = input("Your Gmail address: ").strip()
        # Use App Password (not your regular password)
        self.password = getpass.getpass("Your Gmail App Password: ")
        
    def send_email(self):
        """Send a single email"""
        try:
            # Create message
            msg = MIMEMultipart()
            msg['From'] = self.sender_email
            msg['To'] = self.receiver_email
            msg['Subject'] = self.subject
            
            msg.attach(MIMEText(self.message, 'plain'))
            
            # Connect to SMTP server
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()  # Secure connection
                server.login(self.sender_email, self.password)
                server.send_message(msg)
                
            print(f"Email sent to {self.receiver_email} at {time.strftime('%Y-%m-%d %H:%M:%S')}")
            return True
            
        except Exception as e:
            print(f"Error sending email: {e}")
            return False
    
    def run(self):
        """Main loop to send emails every minute"""
        self.setup_credentials()
        
        print(f"Starting email sender...")
        print(f"From: {self.sender_email}")
        print(f"To: {self.receiver_email}")
        print(f"Message: {self.message}")
        print(f"Interval: 60 seconds")
        print("Press Ctrl+C to stop\n")
        
        try:
            while True:
                self.send_email()
                time.sleep(60)  # Wait 60 seconds
                
        except KeyboardInterrupt:
            print("\nStopped by user")
        except Exception as e:
            print(f"Unexpected error: {e}")

if __name__ == "__main__":
    sender = EmailSender()
    sender.run()
