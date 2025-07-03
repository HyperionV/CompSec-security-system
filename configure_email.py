#!/usr/bin/env python3
"""
Email Configuration Tool for SecurityApp
Configure SMTP settings to enable real email delivery for OTP codes
"""

import getpass
import sys
import os

# Add modules directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.mfa import mfa_manager

def test_smtp_connection(server, port, username, password):
    """Test SMTP connection before saving configuration"""
    try:
        import smtplib
        with smtplib.SMTP(server, port) as smtp:
            smtp.starttls()
            smtp.login(username, password)
        return True, "Connection successful"
    except Exception as e:
        return False, f"Connection failed: {str(e)}"

def configure_email():
    """Configure email settings for SecurityApp"""
    print("=" * 60)
    print("    EMAIL CONFIGURATION - SecurityApp")
    print("=" * 60)
    print("Configure SMTP settings to enable real email delivery for OTP codes.")
    print("Leave blank to use console simulation mode.")
    print()
    
    # Get current status
    current_status = "ENABLED" if mfa_manager.smtp_enabled else "DISABLED (Simulation Mode)"
    print(f"Current Status: {current_status}")
    print()
    
    choice = input("Do you want to configure real email sending? (y/n): ").lower().strip()
    
    if choice != 'y':
        print("Email configuration cancelled. Using simulation mode.")
        return
    
    print("\n" + "=" * 40)
    print("SMTP Configuration")
    print("=" * 40)
    print("Common SMTP Settings:")
    print("Gmail: smtp.gmail.com:587")
    print("Outlook: smtp-mail.outlook.com:587")
    print("Yahoo: smtp.mail.yahoo.com:587")
    print()
    
    # Get SMTP details
    server = input("SMTP Server: ").strip()
    if not server:
        print("No server provided. Keeping simulation mode.")
        return
    
    try:
        port = int(input("SMTP Port (default 587): ").strip() or "587")
    except ValueError:
        print("Invalid port. Using default 587.")
        port = 587
    
    username = input("Email Username: ").strip()
    if not username:
        print("No username provided. Keeping simulation mode.")
        return
    
    password = getpass.getpass("Email Password (App Password recommended): ")
    if not password:
        print("No password provided. Keeping simulation mode.")
        return
    
    from_email = input(f"From Email (default: {username}): ").strip() or username
    
    print("\nTesting SMTP connection...")
    success, message = test_smtp_connection(server, port, username, password)
    
    if success:
        print(f"✅ {message}")
        
        # Save configuration
        mfa_manager.configure_smtp(server, port, username, password, from_email)
        
        print("\n" + "=" * 40)
        print("Configuration Saved Successfully!")
        print("=" * 40)
        print(f"SMTP Server: {server}:{port}")
        print(f"Username: {username}")
        print(f"From Email: {from_email}")
        print("\nReal email delivery is now ENABLED for OTP codes.")
        print("Users will receive OTP codes via email during login.")
        
    else:
        print(f"❌ {message}")
        print("\nSMTP configuration failed. Please check your settings.")
        print("Common issues:")
        print("- Enable 2FA and use App Password for Gmail")
        print("- Check firewall/network settings")
        print("- Verify server and port settings")
        print("\nKeeping simulation mode for now.")

def disable_email():
    """Disable email sending and return to simulation mode"""
    mfa_manager.smtp_enabled = False
    print("Email sending disabled. Switched to simulation mode.")

def show_status():
    """Show current email configuration status"""
    print("\n" + "=" * 40)
    print("Current Email Configuration")
    print("=" * 40)
    
    if mfa_manager.smtp_enabled:
        print("Status: ✅ ENABLED (Real Email Delivery)")
        print(f"SMTP Server: {mfa_manager.smtp_server}:{mfa_manager.smtp_port}")
        print(f"Username: {mfa_manager.smtp_username}")
        print(f"From Email: {mfa_manager.from_email}")
    else:
        print("Status: 📧 SIMULATION MODE")
        print("OTP codes are displayed in console instead of sent via email.")
        print("This is suitable for development and testing.")

def main():
    """Main configuration menu"""
    while True:
        print("\n" + "=" * 40)
        print("Email Configuration Menu")
        print("=" * 40)
        print("1. Configure SMTP Email Sending")
        print("2. Disable Email Sending (Simulation Mode)")
        print("3. Show Current Status")
        print("4. Exit")
        print("-" * 40)
        
        choice = input("Choose option (1-4): ").strip()
        
        if choice == "1":
            configure_email()
        elif choice == "2":
            disable_email()
        elif choice == "3":
            show_status()
        elif choice == "4":
            print("Email configuration completed.")
            break
        else:
            print("Invalid choice. Please select 1-4.")

if __name__ == "__main__":
    main() 