"""
Email service for password reset via Mailjet
"""

import os
from typing import Tuple, Optional
from mailjet_rest import Client
import logging

logger = logging.getLogger(__name__)


class EmailService:
    """Service for sending emails via Mailjet"""
    
    def __init__(self):
        """Initialize Mailjet client with environment variables"""
        self.api_key = os.getenv('MAILJET_API_KEY', '').strip()
        self.api_secret = os.getenv('MAILJET_API_SECRET', '').strip()
        self.from_email = os.getenv('FROM_EMAIL', 'noreply@cryptovault.local').strip()
        self.from_name = os.getenv('FROM_NAME', 'CryptoVault').strip()
        
        if self.api_key and self.api_secret:
            try:
                self.mailjet = Client(auth=(self.api_key, self.api_secret))
                self.enabled = True
            except Exception as e:
                logger.error(f"Failed to initialize Mailjet client: {e}")
                self.mailjet = None
                self.enabled = False
        else:
            self.mailjet = None
            self.enabled = False
            logger.warning("Mailjet credentials not configured. Email service disabled.")
    
    def send_password_reset_email(self, to_email: str, username: str, 
                                 reset_token: str, reset_url: str = None) -> Tuple[bool, Optional[str]]:
        """
        Send password reset email via Mailjet
        
        Args:
            to_email: Recipient email address
            username: Username for personalization
            reset_token: Password reset token
            reset_url: Full reset URL (if provided, will be used instead of token-only)
            
        Returns:
            Tuple (success, error_message)
        """
        if not self.enabled:
            logger.error("Email service not enabled. Mailjet credentials missing.")
            return False, "Email service not configured"
        
        try:
            # Generate reset URL if not provided
            if not reset_url:
                # Default to token-only (client-side will construct URL)
                reset_url = reset_token
            
            html_content = f"""
            <html>
                <body style="font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 20px;">
                    <div style="background-color: #ffffff; padding: 30px; border-radius: 8px; max-width: 600px; margin: 0 auto;">
                        <h2 style="color: #333; text-align: center;">Password Reset Request</h2>
                        
                        <p style="color: #666; font-size: 16px;">
                            Hi <strong>{username}</strong>,
                        </p>
                        
                        <p style="color: #666; font-size: 16px; line-height: 1.6;">
                            We received a request to reset your password for your CryptoVault account. 
                            Click the button below to create a new password.
                        </p>
                        
                        <div style="text-align: center; margin: 30px 0;">
                            <a href="{reset_url}" 
                               style="background-color: #007bff; color: white; padding: 12px 30px; 
                                      text-decoration: none; border-radius: 5px; font-size: 16px; 
                                      display: inline-block;">
                                Reset Password
                            </a>
                        </div>
                        
                        <p style="color: #666; font-size: 14px; line-height: 1.6;">
                            Or copy and paste this link in your browser:
                        </p>
                        
                        <p style="background-color: #f9f9f9; padding: 10px; border-radius: 3px; 
                                  word-break: break-all; color: #007bff; font-size: 12px;">
                            {reset_url}
                        </p>
                        
                        <p style="color: #999; font-size: 12px; margin-top: 30px; border-top: 1px solid #eee; padding-top: 20px;">
                            This password reset link will expire in 1 hour. If you didn't request a password reset, 
                            please ignore this email or contact support if you have concerns.
                        </p>
                        
                        <p style="color: #999; font-size: 12px;">
                            Best regards,<br/>
                            CryptoVault Security Team
                        </p>
                    </div>
                </body>
            </html>
            """
            
            text_content = f"""
Password Reset Request

Hi {username},

We received a request to reset your password for your CryptoVault account. 
Click the link below to create a new password:

{reset_url}

This password reset link will expire in 1 hour. If you didn't request a password reset, 
please ignore this email or contact support.

Best regards,
CryptoVault Security Team
            """
            
            # Prepare email data for Mailjet
            data = {
                'Messages': [
                    {
                        'From': {
                            'Email': self.from_email,
                            'Name': self.from_name
                        },
                        'To': [
                            {
                                'Email': to_email,
                                'Name': username
                            }
                        ],
                        'Subject': 'CryptoVault - Password Reset Request',
                        'TextPart': text_content,
                        'HTMLPart': html_content
                    }
                ]
            }
            
            # Send email via Mailjet
            result = self.mailjet.send.create(data=data)
            
            if result.status_code == 200:
                logger.info(f"Password reset email sent successfully to {to_email}")
                return True, None
            else:
                # Enhanced error message
                response_text = result.text if result.text else "(No response body)"
                
                if result.status_code == 400:
                    error_msg = f"Mailjet API error 400: Bad request. Check that FROM_EMAIL ({self.from_email}) is verified in Mailjet. Response: {response_text}"
                elif result.status_code == 401:
                    error_msg = f"Mailjet API error 401: Invalid API credentials. Response: {response_text}"
                elif result.status_code == 403:
                    error_msg = f"Mailjet API error 403: Forbidden. Your account may be restricted. Response: {response_text}"
                else:
                    error_msg = f"Mailjet API error: {result.status_code} - {response_text}"
                
                logger.error(error_msg)
                return False, error_msg
        
        except Exception as e:
            error_msg = f"Error sending password reset email: {str(e)}"
            logger.error(error_msg)
            return False, error_msg
    
    def send_test_email(self, to_email: str) -> Tuple[bool, Optional[str]]:
        """
        Send a test email to verify Mailjet configuration
        
        Args:
            to_email: Recipient email address
            
        Returns:
            Tuple (success, error_message)
        """
        if not self.enabled:
            return False, "Email service not configured"
        
        try:
            data = {
                'Messages': [
                    {
                        'From': {
                            'Email': self.from_email,
                            'Name': self.from_name
                        },
                        'To': [
                            {
                                'Email': to_email
                            }
                        ],
                        'Subject': 'CryptoVault - Test Email',
                        'TextPart': 'This is a test email from CryptoVault.',
                        'HTMLPart': '<html><body><p>This is a test email from CryptoVault.</p></body></html>'
                    }
                ]
            }
            
            result = self.mailjet.send.create(data=data)
            
            if result.status_code == 200:
                logger.info(f"Test email sent successfully to {to_email}")
                return True, None
            else:
                error_msg = f"Mailjet API error: {result.status_code}"
                logger.error(error_msg)
                return False, error_msg
        
        except Exception as e:
            error_msg = f"Error sending test email: {str(e)}"
            logger.error(error_msg)
            return False, error_msg
