"""
Email service for password reset via Mailjet SMTP
Using native Python smtplib instead of REST API
This approach works better for password reset emails
"""

import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Tuple, Optional
import logging

logger = logging.getLogger(__name__)


class SMTPEmailService:
    """Email service using SMTP instead of REST API"""
    
    def __init__(self):
        """Initialize SMTP email service from environment variables"""
        self.smtp_server = os.getenv('SMTP_SERVER', '').strip()
        self.smtp_port_str = os.getenv('SMTP_PORT', '').strip()
        self.smtp_username = os.getenv('SMTP_USERNAME', '').strip()
        self.smtp_password = os.getenv('SMTP_PASSWORD', '').strip()
        self.from_email = os.getenv('FROM_EMAIL', '').strip() or self.smtp_username
        self.from_name = os.getenv('FROM_NAME', 'CryptoVault').strip()
        
        # Check if all required settings are present
        self.enabled = bool(self.smtp_server and self.smtp_port_str and 
                           self.smtp_username and self.smtp_password)
        
        if self.enabled:
            try:
                self.smtp_port = int(self.smtp_port_str)
            except ValueError:
                logger.error(f"Invalid SMTP_PORT: {self.smtp_port_str}")
                self.enabled = False
                self.smtp_port = None
        else:
            self.smtp_port = None
            logger.warning("SMTP not configured. Email service disabled.")
    
    def send_password_reset_email(self, to_email: str, username: str, 
                                 reset_token: str, reset_url: str = None) -> Tuple[bool, Optional[str]]:
        """
        Send password reset email via SMTP
        
        Args:
            to_email: Recipient email address
            username: Username for personalization
            reset_token: Password reset token
            reset_url: Full reset URL
            
        Returns:
            Tuple (success, error_message)
        """
        if not self.enabled:
            logger.warning("SMTP not configured. Email not sent.")
            return False, "Email service not configured"
        
        try:
            # Create the email message
            msg = MIMEMultipart('alternative')
            msg['From'] = self.from_email
            msg['To'] = to_email
            msg['Subject'] = 'CryptoVault - Password Reset Request'
            
            # Plain text version
            text_content = f"""
Password Reset Request

Hi {username},

We received a request to reset your password for your CryptoVault account.
Click the link below to create a new password:

{reset_url or reset_token}

This password reset link will expire in 1 hour.

If you didn't request a password reset, please ignore this email.

Best regards,
CryptoVault Security Team
            """.strip()
            
            # HTML version
            html_content = f"""
<html>
  <head></head>
  <body>
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
      <h2 style="color: #333;">Password Reset Request</h2>
      <p style="color: #666;">Hi {username},</p>
      <p style="color: #666; line-height: 1.6;">
        We received a request to reset your password for your CryptoVault account.
      </p>
      <div style="text-align: center; margin: 30px 0;">
        <a href="{reset_url or reset_token}" 
           style="background-color: #007bff; color: white; padding: 12px 30px; 
                  text-decoration: none; border-radius: 5px; font-size: 16px;
                  display: inline-block;">
          Reset Password
        </a>
      </div>
      <p style="color: #666; font-size: 14px;">
        Or copy this link: {reset_url or reset_token}
      </p>
      <p style="color: #999; font-size: 12px; margin-top: 30px; border-top: 1px solid #eee; padding-top: 20px;">
        This link expires in 1 hour. If you didn't request a password reset, please ignore this email.
      </p>
      <p style="color: #999; font-size: 12px;">
        Best regards,<br/>CryptoVault Security Team
      </p>
    </div>
  </body>
</html>
            """.strip()
            
            # Attach both plain text and HTML versions
            msg.attach(MIMEText(text_content, 'plain'))
            msg.attach(MIMEText(html_content, 'html'))
            
            # Send the email via SMTP
            logger.info(f"Connecting to SMTP server {self.smtp_server}:{self.smtp_port}")
            
            server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            server.starttls()  # Start TLS encryption
            server.login(self.smtp_username, self.smtp_password)
            server.send_message(msg)
            server.quit()
            
            logger.info(f"✅ Password reset email sent successfully to {to_email}")
            return True, None
        
        except smtplib.SMTPAuthenticationError as e:
            error_msg = f"SMTP authentication failed. Check SMTP_USERNAME and SMTP_PASSWORD. Error: {str(e)}"
            logger.error(error_msg)
            return False, error_msg
        
        except smtplib.SMTPConnectError as e:
            error_msg = f"Cannot connect to SMTP server {self.smtp_server}:{self.smtp_port}. Error: {str(e)}"
            logger.error(error_msg)
            return False, error_msg
        
        except Exception as e:
            error_msg = f"Error sending password reset email: {str(e)}"
            logger.error(error_msg)
            return False, error_msg
    
    def send_test_email(self, to_email: str) -> Tuple[bool, Optional[str]]:
        """Send a test email"""
        
        if not self.enabled:
            return False, "Email service not configured"
        
        try:
            msg = MIMEMultipart()
            msg['From'] = self.from_email
            msg['To'] = to_email
            msg['Subject'] = 'CryptoVault - Test Email'
            msg.attach(MIMEText('This is a test email from CryptoVault.', 'plain'))
            
            server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            server.starttls()
            server.login(self.smtp_username, self.smtp_password)
            server.send_message(msg)
            server.quit()
            
            logger.info(f"✅ Test email sent successfully to {to_email}")
            return True, None
        
        except Exception as e:
            error_msg = f"Error sending test email: {str(e)}"
            logger.error(error_msg)
            return False, error_msg
