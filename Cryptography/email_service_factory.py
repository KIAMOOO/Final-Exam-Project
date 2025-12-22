#!/usr/bin/env python3
"""
Email Service Factory - Automatically selects between SMTP, Mailjet REST, and Local Email Service
Based on configuration and environment
"""

import os
from dotenv import load_dotenv

load_dotenv()


def get_email_service():
    """
    Get appropriate email service based on configuration
    
    Priority:
    1. SMTP (if SMTP_SERVER is set) - Recommended for Mailjet
    2. Mailjet REST API (if API key is set)
    3. Local Email Service (for development)
    
    Returns:
        EmailService instance (SMTP, Mailjet REST, or Local)
    """
    
    # Check configuration options
    smtp_server = os.getenv('SMTP_SERVER', '').strip()
    mailjet_api_key = os.getenv('MAILJET_API_KEY', '').strip()
    mailjet_api_secret = os.getenv('MAILJET_API_SECRET', '').strip()
    use_local = os.getenv('USE_LOCAL_EMAIL', 'false').lower() in ('true', '1', 'yes')
    
    # Priority 1: SMTP (Recommended for Mailjet)
    if smtp_server:
        print("📧 Using SMTP email service (Mailjet)")
        from src.auth.smtp_email_service import SMTPEmailService
        return SMTPEmailService()
    
    # Priority 2: Mailjet REST API
    elif mailjet_api_key and mailjet_api_secret:
        print("📧 Using Mailjet REST API email service")
        from src.auth.email_service import EmailService
        return EmailService()
    
    # Priority 3: Local Email Service (for testing)
    elif use_local:
        print("📧 Using LOCAL email service (for development)")
        from local_email_service import LocalEmailService
        return LocalEmailService()
    
    # Default: Local Email Service
    else:
        print("📧 Using LOCAL email service (default - no email service configured)")
        print("   To use SMTP: export SMTP_SERVER='in-v3.mailjet.com'")
        print("   To use Mailjet REST API: export MAILJET_API_KEY='your_key'")
        from local_email_service import LocalEmailService
        return LocalEmailService()


if __name__ == '__main__':
    print("Email Service Factory Test")
    print("=" * 50)
    
    service = get_email_service()
    print(f"Service type: {type(service).__name__}")
    print(f"Service enabled: {service.enabled if hasattr(service, 'enabled') else 'N/A'}")
