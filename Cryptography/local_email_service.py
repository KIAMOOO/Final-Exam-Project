#!/usr/bin/env python3
"""
Local Email Service Demo - For Testing Without Mailjet
Sends emails to a local file instead of via Mailjet
Useful for development and testing
"""

import os
import json
from datetime import datetime
from typing import Tuple, Optional
import logging

logger = logging.getLogger(__name__)


class LocalEmailService:
    """Local email service for testing (saves emails to files instead of sending)"""
    
    def __init__(self, output_dir='email_logs'):
        """
        Initialize local email service
        
        Args:
            output_dir: Directory to save email logs
        """
        self.output_dir = output_dir
        self.enabled = True
        
        # Create directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)
        
        print(f"📧 Local Email Service initialized")
        print(f"   Emails will be saved to: {output_dir}/")
    
    def send_password_reset_email(self, to_email: str, username: str, 
                                 reset_token: str, reset_url: str = None) -> Tuple[bool, Optional[str]]:
        """
        Simulate sending password reset email (saves to file)
        
        Args:
            to_email: Recipient email
            username: Username
            reset_token: Reset token
            reset_url: Reset URL
            
        Returns:
            Tuple (success, error_message)
        """
        try:
            # Create email content
            email_data = {
                'type': 'password_reset',
                'timestamp': datetime.now().isoformat(),
                'to_email': to_email,
                'username': username,
                'subject': 'CryptoVault - Password Reset Request',
                'reset_token': reset_token,
                'reset_url': reset_url,
                'plain_text': f"""
Password Reset Request

Hi {username},

We received a request to reset your password for your CryptoVault account.
Click the link below to create a new password:

{reset_url or reset_token}

This password reset link will expire in 1 hour.

Best regards,
CryptoVault Security Team
                """.strip(),
                'html': f"""
<html>
  <body>
    <h2>Password Reset Request</h2>
    <p>Hi {username},</p>
    <p>Click the button below to reset your password:</p>
    <a href="{reset_url or reset_token}" style="background: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block;">Reset Password</a>
    <p>Or copy this link: {reset_url or reset_token}</p>
    <p style="color: #999; font-size: 12px;">Link expires in 1 hour.</p>
  </body>
</html>
                """.strip()
            }
            
            # Save to file
            filename = f"{self.output_dir}/email_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{to_email.replace('@', '_at_')}.json"
            with open(filename, 'w') as f:
                json.dump(email_data, f, indent=2)
            
            print(f"\n✅ Email saved to: {filename}")
            print(f"   To: {to_email}")
            print(f"   Token: {reset_token}")
            print(f"   Reset URL: {reset_url}\n")
            
            return True, None
        
        except Exception as e:
            error_msg = f"Error saving email: {str(e)}"
            logger.error(error_msg)
            return False, error_msg
    
    def send_test_email(self, to_email: str) -> Tuple[bool, Optional[str]]:
        """Send a test email (saves to file)"""
        
        try:
            email_data = {
                'type': 'test',
                'timestamp': datetime.now().isoformat(),
                'to_email': to_email,
                'subject': 'CryptoVault - Test Email',
                'body': 'This is a test email from CryptoVault.'
            }
            
            filename = f"{self.output_dir}/email_test_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(filename, 'w') as f:
                json.dump(email_data, f, indent=2)
            
            print(f"✅ Test email saved to: {filename}")
            return True, None
        
        except Exception as e:
            error_msg = f"Error saving test email: {str(e)}"
            logger.error(error_msg)
            return False, error_msg


def main():
    """Demo of local email service"""
    
    print("=" * 70)
    print("LOCAL EMAIL SERVICE DEMO")
    print("=" * 70)
    print()
    
    # Create service
    service = LocalEmailService('email_logs')
    print()
    
    # Test 1: Send test email
    print("Test 1: Sending test email...")
    success, error = service.send_test_email('user@example.com')
    if success:
        print("✅ Test email saved successfully\n")
    else:
        print(f"❌ Error: {error}\n")
    
    # Test 2: Send password reset email
    print("Test 2: Sending password reset email...")
    success, error = service.send_password_reset_email(
        to_email='john_doe@example.com',
        username='john_doe',
        reset_token='test_token_abc123xyz',
        reset_url='http://localhost:5000/reset_password/test_token_abc123xyz'
    )
    if success:
        print("✅ Password reset email saved successfully\n")
    else:
        print(f"❌ Error: {error}\n")
    
    # Show files
    print("Files saved in email_logs/:")
    files = os.listdir('email_logs')
    for f in sorted(files):
        print(f"  • {f}")
    print()


if __name__ == '__main__':
    main()
