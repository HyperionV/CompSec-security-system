#!/usr/bin/env python3
"""
Security Application - Main Entry Point
A comprehensive security application with PyQt5 GUI interface
"""

import sys
import os
import getpass
from typing import Optional, Dict
import threading
import time

# Add modules directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.database import db
from modules.logger import security_logger
from modules.auth import auth_manager
from modules.mfa import mfa_manager
from modules.key_manager import key_manager
from modules.key_lifecycle import lifecycle_service
from modules.qr_handler import qr_handler
from modules.file_crypto import file_crypto
from modules.digital_signature import DigitalSignature
from modules.signature_verification import SignatureVerification
from modules.public_key_manager import PublicKeyManager
from datetime import datetime

# Utility functions for safe datetime handling
def safe_to_datetime(dt_value):
    """Convert string or datetime to datetime object safely"""
    if dt_value is None:
        return None
    if isinstance(dt_value, datetime):
        return dt_value
    if isinstance(dt_value, str):
        return datetime.fromisoformat(dt_value)
    return datetime.fromisoformat(str(dt_value))

def safe_to_isoformat(dt_value):
    """Convert string or datetime to ISO format string safely"""
    if dt_value is None:
        return None
    if isinstance(dt_value, str):
        return dt_value  # Already a string
    if hasattr(dt_value, 'isoformat'):
        return dt_value.isoformat()
    return str(dt_value)  # fallback to string conversion

def safe_strftime(dt_value, format_str):
    """Safely format datetime or string to specified format"""
    if dt_value is None:
        return 'N/A'
    if isinstance(dt_value, str):
        try:
            # Try to parse string as datetime first
            dt_obj = datetime.fromisoformat(dt_value)
            return dt_obj.strftime(format_str)
        except:
            return dt_value  # Return as-is if can't parse
    if hasattr(dt_value, 'strftime'):
        return dt_value.strftime(format_str)
    return str(dt_value)  # fallback

class UserSession:
    """Manage user session state"""
    def __init__(self):
        self.user_info = None
        self.is_authenticated = False
        self.mfa_completed = False
    
    def login(self, user_info: Dict):
        self.user_info = user_info
        self.is_authenticated = True
    
    def complete_mfa(self):
        self.mfa_completed = True
    
    def logout(self):
        self.user_info = None
        self.is_authenticated = False
        self.mfa_completed = False
    
    def is_fully_authenticated(self) -> bool:
        return self.is_authenticated and self.mfa_completed

# Global session instance
user_session = UserSession()

def initialize_application():
    """Initialize the security application"""
    print("=== Security Application ===")
    print("Initializing system components...")
    
    # Create necessary directories
    os.makedirs("data", exist_ok=True)
    os.makedirs("data/qr_codes", exist_ok=True)
    
    # Initialize database
    print("- Setting up database...")
    if db.initialize_database():
        print("  ✓ Database initialized successfully")
    else:
        print("  ✗ Database initialization failed")
        security_logger.log_activity(action='app_start', status='failure', details='Database initialization failed')
        return False
    
    # Initialize key lifecycle service
    print("- Initializing key lifecycle management...")
    try:
        # Run daily lifecycle check on startup
        lifecycle_service.run_daily_lifecycle_check()
        print("  ✓ Key lifecycle management initialized")
    except Exception as e:
        print(f"  ⚠ Key lifecycle warning: {str(e)}")
    
    print("- Logging system active")
    print("✓ Application initialized successfully")
    security_logger.log_activity(action='app_start', status='success', details='Application started')
    return True

def clear_screen():
    """Clear the terminal screen"""
    os.system('cls' if os.name == 'nt' else 'clear')

def show_welcome():
    """Display welcome message"""
    clear_screen()
    print("=" * 60)
    print("    SECURITY APPLICATION - CRYPTOGRAPHIC SYSTEM")
    print("=" * 60)
    print("A comprehensive security application with RSA key management,")
    print("multi-factor authentication, and cryptographic features.")
    print("=" * 60)

def show_main_menu():
    """Display main menu for unauthenticated users"""
    print("\n🔐 MAIN MENU")
    print("-" * 30)
    print("1. Register New Account")
    print("2. Login to Account")
    print("3. Forgot Password (Account Recovery)")
    print("4. Exit Application")
    print("-" * 30)

def show_authenticated_menu():
    print("\n=== SECURITY APPLICATION ===")
    print("1. QR Code Operations")
    print("2. Key Status and Management")
    print("3. Update Account Information")
    print("4. File Encryption Operations")
    print("5. Digital Signature Operations")
    print("6. Public Key Search and Management")
    
    # Show admin option only for admin users
    current_user = user_session.user_info
    if current_user and current_user.get('role') == 'admin':
        print("7. Admin Panel")
        print("8. View Account Status")
        print("9. Logout")
    else:
        print("7. View Account Status")
        print("8. Logout")
    
    print("-" * 50)

def show_account_menu():
    """Display account management menu"""
    print("\n📋 ACCOUNT MANAGEMENT")
    print("-" * 30)
    print("1. Update Profile Information")
    print("2. Change Passphrase")
    print("3. View Activity Log")
    print("4. Back to Main Menu")
    print("-" * 30)

def show_key_management_menu():
    """Display key management menu"""
    print("\n🔑 KEY MANAGEMENT")
    print("-" * 30)
    print("1. View Key Status")
    print("2. Generate New Keys")
    print("3. Renew Existing Keys")
    print("4. Key Security Information")
    print("5. Back to Main Menu")
    print("-" * 30)

def show_qr_code_menu():
    """Display QR code operations menu"""
    print("\n📱 QR CODE OPERATIONS")
    print("-" * 30)
    print("1. Generate QR Code for My Public Key")
    print("2. Import Public Key from QR Code")
    print("3. List Imported Public Keys")
    print("4. Search Public Key by Email")
    print("5. Back to Main Menu")
    print("-" * 30)

def show_file_encryption_menu():
    """Display file encryption operations menu"""
    print("\n🔒 FILE ENCRYPTION OPERATIONS")
    print("-" * 40)
    print("1. Encrypt File for Someone")
    print("2. Decrypt File")
    print("3. List Public Keys (Recipients)")
    print("4. Back to Main Menu")
    print("-" * 40)

def handle_user_registration():
    """Handle user registration process"""
    print("\n📝 USER REGISTRATION")
    print("-" * 30)
    
    try:
        email = input("Email: ").strip()
        name = input("Full Name: ").strip()
        phone = input("Phone (optional): ").strip() or None
        address = input("Address (optional): ").strip() or None
        birth_date = input("Birth Date (YYYY-MM-DD, optional): ").strip() or None
        
        print("\nEnter a strong passphrase:")
        passphrase = getpass.getpass("Passphrase: ")
        confirm_passphrase = getpass.getpass("Confirm Passphrase: ")
        
        if passphrase != confirm_passphrase:
            print("❌ Passphrases do not match!")
            return
        
        success, message = auth_manager.register_user(
            email=email, name=name, password=passphrase,
            phone=phone, address=address, birth_date=birth_date
        )
        
        if success:
            print(f"✅ {message}")
            input("\nPress Enter to continue...")
        else:
            print(f"❌ Registration failed: {message}")
            input("\nPress Enter to continue...")
    
    except Exception as e:
        print(f"❌ Registration error: {str(e)}")
        input("\nPress Enter to continue...")

def handle_user_login():
    """Handle user login process with MFA"""
    print("\n🔐 USER LOGIN")
    print("-" * 30)
    
    try:
        email = input("Email: ").strip()
        passphrase = getpass.getpass("Passphrase: ")
        
        # Step 1: Verify credentials
        success, message, user_info = auth_manager.initiate_login_flow(email, passphrase)
        
        if not success:
            print(f"❌ {message}")
            input("\nPress Enter to continue...")
            return
        
        print(f"✅ {message}")
        user_session.login(user_info)
        
        # Step 2: MFA Challenge
        print("\n🔒 MULTI-FACTOR AUTHENTICATION")
        print("Choose your MFA method:")
        print("1. Email OTP")
        print("2. TOTP (Google Authenticator)")
        
        mfa_choice = input("Choose (1-2): ").strip()
        
        if mfa_choice == "1":
            # Email OTP
            otp_success, otp_message = mfa_manager.send_otp(user_info['id'])
            if otp_success:
                print(f"✅ {otp_message}")
                otp_code = input("Enter 6-digit OTP code: ").strip()
                
                login_success, login_message = auth_manager.complete_login_with_mfa(
                    user_info, otp_code, "otp"
                )
                
                if login_success:
                    user_session.complete_mfa()
                    print(f"✅ {login_message}")
                    input("\nPress Enter to continue...")
                else:
                    print(f"❌ {login_message}")
                    user_session.logout()
                    input("\nPress Enter to continue...")
            else:
                print(f"❌ {otp_message}")
                user_session.logout()
                input("\nPress Enter to continue...")
                
        elif mfa_choice == "2":
            # TOTP
            totp_code = input("Enter 6-digit TOTP code from authenticator app: ").strip()
            
            login_success, login_message = auth_manager.complete_login_with_mfa(
                user_info, totp_code, "totp"
            )
            
            if login_success:
                user_session.complete_mfa()
                print(f"✅ {login_message}")
                input("\nPress Enter to continue...")
            else:
                print(f"❌ {login_message}")
                user_session.logout()
                input("\nPress Enter to continue...")
        else:
            print("❌ Invalid MFA choice")
            user_session.logout()
            input("\nPress Enter to continue...")
    
    except Exception as e:
        print(f"❌ Login error: {str(e)}")
        user_session.logout()
        input("\nPress Enter to continue...")

def handle_profile_update():
    """Handle profile information updates"""
    print("\n📝 UPDATE PROFILE")
    print("-" * 30)
    
    try:
        print("Leave fields blank to keep current values:")
        name = input("Full Name: ").strip() or None
        phone = input("Phone: ").strip() or None
        address = input("Address: ").strip() or None
        birth_date = input("Birth Date (YYYY-MM-DD): ").strip() or None
        
        success, message = auth_manager.update_user_profile(
            user_session.user_info['id'], name=name, phone=phone,
            address=address, birth_date=birth_date
        )
        
        if success:
            print(f"✅ {message}")
        else:
            print(f"❌ {message}")
        
        input("\nPress Enter to continue...")
    
    except Exception as e:
        print(f"❌ Update error: {str(e)}")
        input("\nPress Enter to continue...")

def handle_passphrase_change():
    """Handle passphrase change with key re-encryption"""
    print("\n🔑 CHANGE PASSPHRASE")
    print("-" * 30)
    print("Note: This will re-encrypt all your RSA keys with the new passphrase.")
    
    try:
        current_passphrase = getpass.getpass("Current Passphrase: ")
        new_passphrase = getpass.getpass("New Passphrase: ")
        confirm_passphrase = getpass.getpass("Confirm New Passphrase: ")
        
        if new_passphrase != confirm_passphrase:
            print("❌ New passphrases do not match!")
            input("\nPress Enter to continue...")
            return
        
        success, message = auth_manager.change_passphrase(
            user_session.user_info['id'], current_passphrase, new_passphrase
        )
        
        if success:
            print(f"✅ {message}")
        else:
            print(f"❌ {message}")
        
        input("\nPress Enter to continue...")
    
    except Exception as e:
        print(f"❌ Passphrase change error: {str(e)}")
        input("\nPress Enter to continue...")

def handle_view_account_status():
    """Display comprehensive account status"""
    print("\n📊 ACCOUNT STATUS")
    print("-" * 40)
    
    try:
        status = auth_manager.get_account_status(user_session.user_info['email'])
        
        print(f"User ID: {status['user_id']}")
        print(f"Email: {user_session.user_info['email']}")
        print(f"Name: {user_session.user_info['name']}")
        print(f"Role: {status['role']}")
        print(f"Account Created: {status['created_at']}")
        print(f"Failed Login Attempts: {status['failed_attempts']}")
        
        if status['key_status']:
            key_status = status['key_status']
            print(f"\n🔑 RSA Key Status: {key_status['status'].upper()}")
            print(f"Key Created: {key_status['created_at']}")
            print(f"Key Expires: {key_status['expires_at']}")
            if key_status['status'] == 'expiring':
                print(f"⚠️  Days until expiry: {key_status['days_until_expiry']}")
        else:
            print("\n🔑 RSA Keys: Not generated")
        
        input("\nPress Enter to continue...")
    
    except Exception as e:
        print(f"❌ Status error: {str(e)}")
        input("\nPress Enter to continue...")

def handle_key_status():
    """Display detailed key status information"""
    print("\n🔑 KEY STATUS")
    print("-" * 30)
    
    try:
        success, message, key_status = key_manager.check_key_status(user_session.user_info['id'])
        
        if success and key_status:
            print(f"Status: {key_status['status'].upper()}")
            print(f"Created: {key_status['created_at']}")
            print(f"Expires: {key_status['expires_at']}")
            
            if key_status['status'] == 'valid':
                print("✅ Your keys are valid and ready for use")
            elif key_status['status'] == 'expiring':
                print(f"⚠️  Keys expiring in {key_status['days_until_expiry']} days")
                print("Consider renewing your keys soon")
            elif key_status['status'] == 'expired':
                print("❌ Keys have expired - renewal required")
        else:
            print("ℹ️  No RSA keys found for your account")
            print("Generate new keys to enable cryptographic features")
        
        input("\nPress Enter to continue...")
    
    except Exception as e:
        print(f"❌ Key status error: {str(e)}")
        input("\nPress Enter to continue...")

def handle_generate_keys():
    """Generate new RSA keys for user"""
    print("\n🔑 GENERATE NEW RSA KEYS")
    print("-" * 30)
    print("This will generate a new 2048-bit RSA key pair for your account.")
    
    try:
        passphrase = getpass.getpass("Enter passphrase for key encryption: ")
        
        success, message = auth_manager.generate_new_keys(
            user_session.user_info['id'], passphrase
        )
        
        if success:
            print(f"✅ {message}")
        else:
            print(f"❌ {message}")
        
        input("\nPress Enter to continue...")
    
    except Exception as e:
        print(f"❌ Key generation error: {str(e)}")
        input("\nPress Enter to continue...")

def handle_renew_keys():
    """Renew existing RSA keys"""
    print("\n🔑 RENEW RSA KEYS")
    print("-" * 30)
    print("This will generate new keys and expire the old ones.")
    
    try:
        passphrase = getpass.getpass("Enter passphrase for new keys: ")
        
        success, message = auth_manager.renew_user_keys(
            user_session.user_info['id'], passphrase
        )
        
        if success:
            print(f"✅ {message}")
        else:
            print(f"❌ {message}")
        
        input("\nPress Enter to continue...")
    
    except Exception as e:
        print(f"❌ Key renewal error: {str(e)}")
        input("\nPress Enter to continue...")

def handle_key_security_info():
    """Display key security information"""
    print("\n🔒 KEY SECURITY INFORMATION")
    print("-" * 40)
    print("RSA Key Management Security Features:")
    print("• 2048-bit RSA keys with public exponent 65537")
    print("• Private keys encrypted with AES-256-GCM")
    print("• PBKDF2 key derivation with 200,000 iterations")
    print("• PEM format storage (SubjectPublicKeyInfo/PKCS#8)")
    print("• 90-day key expiration with 7-day warnings")
    print("• Automatic key lifecycle management")
    print("• Secure key rotation capabilities")
    print("\nYour cryptographic keys are protected using industry-standard")
    print("security practices and are automatically managed for optimal security.")
    
    input("\nPress Enter to continue...")

def handle_generate_qr_code():
    """Generate QR code for user's public key"""
    print("\n📱 GENERATE PUBLIC KEY QR CODE")
    print("-" * 40)
    
    try:
        success, result = qr_handler.generate_user_public_key_qr(
            user_session.user_info['id'], 
            user_session.user_info['email']
        )
        
        if success:
            print(f"✅ QR code generated successfully!")
            print(f"📁 Saved to: {result['filepath']}")
            print(f"📧 Email: {result['email']}")
            print(f"📅 Creation Date: {result['creation_date']}")
            print("\nShare this QR code with others to allow them to encrypt files for you.")
        else:
            print(f"❌ Failed to generate QR code: {result}")
        
        input("\nPress Enter to continue...")
    
    except Exception as e:
        print(f"❌ QR code generation error: {str(e)}")
        input("\nPress Enter to continue...")

def handle_import_qr_code():
    """Import public key from QR code"""
    print("\n📱 IMPORT PUBLIC KEY FROM QR CODE")
    print("-" * 40)
    
    try:
        print("Enter the path to the QR code image file:")
        print("(You can drag and drop the file or enter the full path)")
        image_path = input("Image Path: ").strip().strip('"\'')
        
        if not image_path:
            print("❌ No image path provided.")
            input("\nPress Enter to continue...")
            return
        
        success, result = qr_handler.import_public_key_from_qr(
            user_session.user_info['id'], 
            image_path
        )
        
        if success:
            print(f"✅ {result['message']}")
            print(f"📧 Owner Email: {result['owner_email']}")
            print(f"📅 Key Creation Date: {result['creation_date']}")
            print(f"🆔 Key ID: {result['key_id']}")
            print("\nYou can now encrypt files for this person.")
        else:
            print(f"❌ Failed to import public key: {result}")
        
        input("\nPress Enter to continue...")
    
    except Exception as e:
        print(f"❌ Import error: {str(e)}")
        input("\nPress Enter to continue...")

def handle_list_imported_keys():
    """List all imported public keys"""
    print("\n📱 IMPORTED PUBLIC KEYS")
    print("-" * 40)
    
    try:
        from modules.database import db
        
        keys = db.get_public_keys_by_user(user_session.user_info['id'])
        
        if not keys:
            print("ℹ️  No public keys imported yet.")
            print("Use 'Import Public Key from QR Code' to add keys from others.")
        else:
            print(f"Found {len(keys)} imported public key(s):\n")
            for i, key in enumerate(keys, 1):
                print(f"{i}. 📧 {key['owner_email']}")
                print(f"   📅 Key Created: {key['creation_date']}")
                print(f"   📥 Imported: {safe_strftime(key['imported_at'], '%Y-%m-%d %H:%M')}")
                print(f"   🆔 Key ID: {key['id']}")
                print()
        
        input("Press Enter to continue...")
    
    except Exception as e:
        print(f"❌ Error listing keys: {str(e)}")
        input("\nPress Enter to continue...")

def handle_search_public_key():
    """Handle searching for public key by email"""
    print("\n🔍 SEARCH PUBLIC KEY BY EMAIL")
    print("-" * 40)
    
    email = input("Enter email to search for: ").strip()
    if not email:
        print("❌ Email cannot be empty")
        input("Press Enter to continue...")
        return
    
    # Search for public key
    public_key_data = db.search_public_key_by_email(user_session.user_id, email)
    
    if public_key_data:
        print(f"\n✅ Public key found for {email}")
        print(f"📧 Owner: {public_key_data['owner_email']}")
        print(f"📅 Creation Date: {public_key_data['creation_date']}")
        print(f"📥 Imported: {public_key_data['imported_at']}")
        print(f"🔗 Key ID: {public_key_data['id']}")
    else:
        print(f"❌ No public key found for {email}")
        print("💡 To encrypt files for this person, you need their public key QR code first.")
    
    input("\nPress Enter to continue...")

def handle_encrypt_file():
    """Handle file encryption"""
    print("\n🔒 ENCRYPT FILE FOR SOMEONE")
    print("-" * 40)
    
    # Get file path
    file_path = input("Enter path to file to encrypt: ").strip()
    if not file_path:
        print("❌ File path cannot be empty")
        input("Press Enter to continue...")
        return
    
    if not os.path.exists(file_path):
        print(f"❌ File not found: {file_path}")
        input("Press Enter to continue...")
        return
    
    # Get recipient email
    recipient_email = input("Enter recipient's email: ").strip()
    if not recipient_email:
        print("❌ Recipient email cannot be empty")
        input("Press Enter to continue...")
        return
    
    # Check if recipient's public key exists
    public_key_data = db.search_public_key_by_email(user_session.user_id, recipient_email)
    if not public_key_data:
        print(f"❌ No public key found for {recipient_email}")
        print("💡 Import their public key using QR Code Operations first.")
        input("Press Enter to continue...")
        return
    
    # Choose output format
    print("\nChoose output format:")
    print("1. Combined format (single .enc file)")
    print("2. Separate format (.enc + .key files)")
    format_choice = input("Enter choice (1-2): ").strip()
    
    output_format = 'combined' if format_choice == '1' else 'separate'
    
    print(f"\n🔄 Encrypting file for {recipient_email}...")
    
    # Encrypt the file
    success, message, result = file_crypto.encrypt_file(
        file_path, recipient_email, user_session.user_id, output_format
    )
    
    if success:
        print(f"✅ {message}")
        print(f"\n📁 Encrypted file: {result['encrypted_file']}")
        if 'key_file' in result:
            print(f"🔑 Key file: {result['key_file']}")
        print(f"📦 Format: {result['format']}")
        print(f"👤 Recipient: {result['metadata']['recipient_email']}")
        print(f"📝 Original file: {result['metadata']['original_filename']}")
        print(f"📊 File size: {result['metadata']['file_size']} bytes")
    else:
        print(f"❌ {message}")
    
    input("\nPress Enter to continue...")

def handle_decrypt_file():
    """Handle file decryption"""
    print("\n🔓 DECRYPT FILE")
    print("-" * 40)
    
    # Get encrypted file path
    enc_file_path = input("Enter path to encrypted file (.enc): ").strip()
    if not enc_file_path:
        print("❌ File path cannot be empty")
        input("Press Enter to continue...")
        return
    
    if not os.path.exists(enc_file_path):
        print(f"❌ File not found: {enc_file_path}")
        input("Press Enter to continue...")
        return
    
    # Check if key file is needed (for separate format)
    key_file_path = None
    if not enc_file_path.endswith('.enc'):
        print("⚠️  File should have .enc extension")
    
    # Ask for key file (optional for combined format)
    key_file_input = input("Enter path to key file (.key) if separate format (or press Enter to skip): ").strip()
    if key_file_input and os.path.exists(key_file_input):
        key_file_path = key_file_input
    
    # Get passphrase for private key
    passphrase = input("Enter your passphrase to decrypt: ").strip()
    if not passphrase:
        print("❌ Passphrase cannot be empty")
        input("Press Enter to continue...")
        return
    
    print(f"\n🔄 Decrypting file...")
    
    # Decrypt the file
    success, message, result = file_crypto.decrypt_file(
        enc_file_path, user_session.user_id, passphrase, key_file_path
    )
    
    if success:
        print(f"✅ {message}")
        print(f"\n📁 Decrypted file: {result['decrypted_file']}")
        print(f"📝 Original filename: {result['metadata']['original_filename']}")
        print(f"👤 Sender: {result['metadata']['sender_email']}")
        print(f"📊 File size: {result['file_size']} bytes")
        print(f"📅 Encrypted on: {result['metadata']['timestamp']}")
    else:
        print(f"❌ {message}")
    
    input("\nPress Enter to continue...")

def handle_list_recipients():
    """Handle listing available recipients (public keys)"""
    print("\n📧 LIST PUBLIC KEYS (RECIPIENTS)")
    print("-" * 40)
    
    # Get all public keys for current user
    public_keys = db.get_public_keys_by_user(user_session.user_id)
    
    if not public_keys:
        print("❌ No public keys found")
        print("💡 Import public keys using QR Code Operations to encrypt files for others.")
    else:
        print(f"Found {len(public_keys)} public keys:")
        print()
        for i, key_data in enumerate(public_keys, 1):
            status = "✅ Active" if key_data['is_active'] else "❌ Inactive"
            print(f"{i}. 📧 {key_data['owner_email']}")
            print(f"   📅 Created: {key_data['creation_date']}")
            print(f"   📥 Imported: {key_data['imported_at']}")
            print(f"   🔗 Status: {status}")
            print()
    
    input("Press Enter to continue...")

def handle_digital_signature_operations(user_email, key_manager, db, logger):
    digital_signature = DigitalSignature(user_email, key_manager, db, logger)
    signature_verification = SignatureVerification(user_email, db, logger)
    
    while True:
        print("\n=== DIGITAL SIGNATURE OPERATIONS ===")
        print("1. Sign a file")
        print("2. Verify a signature")
        print("3. Back to main menu")
        
        choice = input("\nSelect an option: ").strip()
                
        if choice == "1":
            handle_sign_file(digital_signature)
        elif choice == "2":
            handle_verify_signature(signature_verification)
        elif choice == "3":
            break
        else:
            print("Invalid option. Please try again.")

def handle_sign_file(digital_signature):
    print("\n=== SIGN FILE ===")
    
    file_path = input("Enter the path to the file you want to sign: ").strip()
    if not file_path:
        print("File path cannot be empty.")
        return
    
    if not os.path.isfile(file_path):
        print("File not found. Please check the path and try again.")
        return
    
    passphrase = getpass("Enter your passphrase to access private key: ")
    if not passphrase:
        print("Passphrase cannot be empty.")
        return
    
    print("Signing file...")
    success, result = digital_signature.sign_file(file_path, passphrase)
    
    if success:
        print(f"\nFile signed successfully!")
        print(f"Signature saved to: {result}")
        
        file_size = os.path.getsize(file_path)
        sig_size = os.path.getsize(result)
        
        print(f"\nSigning Details:")
        print(f"Original file: {os.path.basename(file_path)} ({file_size} bytes)")
        print(f"Signature file: {os.path.basename(result)} ({sig_size} bytes)")
        print(f"Signer: {user_email}")
        print(f"Algorithm: SHA-256 + RSA-PSS")
            
    else:
        print(f"\nSigning failed: {result}")

def handle_verify_signature(signature_verification):
    print("\n=== SIGNATURE VERIFICATION ===")
    
    file_path = input("Enter the path to the original file: ").strip()
    if not file_path:
        print("File path cannot be empty.")
        return
    
    signature_path = input("Enter the path to the signature file (leave empty for auto-detection): ").strip()
    if not signature_path:
        signature_path = None
    
    print("\nVerifying signature...")
    result = signature_verification.verify_signature(file_path, signature_path)
    
    if result[0]:  # Success
        print(f"✓ {result[1]}")
        if len(result) > 2:  # Has metadata
            metadata = result[2]
            print(f"  Original filename: {metadata.get('original_filename', 'N/A')}")
            print(f"  File hash: {metadata.get('file_hash', 'N/A')[:16]}...")
            print(f"  Algorithm: {metadata.get('algorithm', 'N/A')}")
            print(f"  Padding: {metadata.get('padding', 'N/A')}")
    else:  # Failure
        print(f"✗ {result[1]}")

def handle_public_key_management(public_key_manager):
    while True:
        print("\n=== PUBLIC KEY SEARCH AND MANAGEMENT ===")
        print("1. List all available public keys")
        print("2. Search keys by email address")
        print("3. View valid recipients for encryption")
        print("4. Back to main menu")
        
        choice = input("\nSelect an option: ").strip()
                
        if choice == "1":
            handle_list_all_keys(public_key_manager)
        elif choice == "2":
            handle_search_keys_by_email(public_key_manager)
        elif choice == "3":
            handle_view_encryption_recipients(public_key_manager)
        elif choice == "4":
            break
        else:
            print("Invalid option. Please try again.")

def handle_list_all_keys(public_key_manager):
    print("\n=== ALL AVAILABLE PUBLIC KEYS ===")
    success, result = public_key_manager.get_all_available_keys()
    
    if not success:
        print(f"Error: {result}")
        return
    
    if not result:
        print("No public keys found.")
        return
    
    print(f"\nFound {len(result)} public key(s):\n")
    for i, key_info in enumerate(result, 1):
        display_info = public_key_manager.format_key_display(key_info)
        print(f"{i}. Email: {display_info['email']}")
        print(f"   Status: {display_info['status_symbol']} {display_info['status'].replace('_', ' ').title()}")
        print(f"   Created: {display_info['created_date']}")
        print(f"   Expires: {display_info['expiry_date']} ({display_info['days_remaining']} days remaining)")
        print(f"   Source: {display_info['source'].replace('_', ' ').title()}")
        print()

def handle_search_keys_by_email(public_key_manager):
    print("\n=== SEARCH KEYS BY EMAIL ===")
    search_email = input("Enter email address to search: ").strip()
    
    if not search_email:
        print("Please enter a valid email address.")
        return
    
    success, result = public_key_manager.search_keys_by_email(search_email)
    
    if not success:
        print(f"Error: {result}")
        return
    
    if not result:
        print(f"No public keys found for email: {search_email}")
        return
    
    print(f"\nFound {len(result)} public key(s) for '{search_email}':\n")
    for i, key_info in enumerate(result, 1):
        display_info = public_key_manager.format_key_display(key_info)
        print(f"{i}. Email: {display_info['email']}")
        print(f"   Status: {display_info['status_symbol']} {display_info['status'].replace('_', ' ').title()}")
        print(f"   Created: {display_info['created_date']}")
        print(f"   Expires: {display_info['expiry_date']} ({display_info['days_remaining']} days remaining)")
        print(f"   Source: {display_info['source'].replace('_', ' ').title()}")
        print()

def handle_view_encryption_recipients(public_key_manager):
    print("\n=== VALID RECIPIENTS FOR ENCRYPTION ===")
    success, recipients = public_key_manager.get_valid_recipients_for_encryption()
    
    if not success:
        print(f"Error: {recipients}")
        return
    
    if not recipients:
        print("No valid recipients available for encryption.")
        print("Import or generate public keys first.")
        return
    
    print(f"Available recipients ({len(recipients)}):\n")
    for i, recipient in enumerate(recipients, 1):
        print(f"{i}. {recipient['display']}")
    
    print("\nThese recipients can be used for file encryption.")

def handle_authenticated_user(user_email):
    digital_signature = DigitalSignature(user_email, key_manager, db, security_logger)
    signature_verification = SignatureVerification(user_email, db, security_logger)
    public_key_manager = PublicKeyManager(user_email, db, security_logger)
    
    while True:
        show_authenticated_menu()
        choice = input("\nSelect an option: ").strip()
        
        current_user = user_session.user_info
        is_admin = current_user and current_user.get('role') == 'admin'
        
        if choice == "1":
            handle_qr_operations(user_email, db, security_logger)
        elif choice == "2":
            handle_key_status_and_management(user_email, key_manager, db, security_logger)
        elif choice == "3":
            handle_update_account_information(user_email, db, security_logger)
        elif choice == "4":
            handle_file_encryption_operations(user_email, key_manager, db, security_logger)
        elif choice == "5":
            handle_digital_signature_operations(user_email, key_manager, db, security_logger)
        elif choice == "6":
            handle_public_key_management(public_key_manager)
        elif choice == "7":
            if is_admin:
                handle_admin_panel()
            else:
                handle_view_account_status()
        elif choice == "8":
            if is_admin:
                handle_view_account_status()
            else:
                security_logger.log_action(user_email, "logout", "success", "User logged out successfully")
                print("Logged out successfully.")
                break
        elif choice == "9" and is_admin:
            security_logger.log_action(user_email, "logout", "success", "User logged out successfully")
            print("Logged out successfully.")
            break
        else:
            print("Invalid option. Please try again.")

def admin_required(func):
    """Decorator to ensure only admin users can access admin functions"""
    def wrapper(*args, **kwargs):
        current_user = user_session.user_info
        if not current_user or current_user.get('role') != 'admin':
            print("\n❌ Access denied: Admin privileges required")
            security_logger.log_activity(
                user_id=current_user.get('id') if current_user else None,
                action='admin_access_denied',
                status='failure',
                details='Non-admin user attempted to access admin functionality'
            )
            input("Press Enter to continue...")
            return None
        return func(*args, **kwargs)
    return wrapper

@admin_required
def handle_admin_panel():
    """Main admin panel interface"""
    while True:
        print("\n=== ADMIN PANEL ===")
        print("🔧 System Administration")
        print("-" * 30)
        print("1. Dashboard & Statistics")
        print("2. User Account Management")
        print("3. System Activity Logs")
        print("4. User Role Management")
        print("5. Back to Main Menu")
        print("-" * 30)
        
        choice = input("\nSelect an option: ").strip()
        
        if choice == "1":
            handle_admin_dashboard()
        elif choice == "2":
            handle_user_account_management()
        elif choice == "3":
            handle_system_logs_viewing()
        elif choice == "4":
            handle_user_role_management()
        elif choice == "5":
            break
        else:
            print("Invalid option. Please try again.")

@admin_required
def handle_admin_dashboard():
    """Display system statistics and overview"""
    print("\n=== ADMIN DASHBOARD ===")
    print("📊 System Statistics")
    print("-" * 30)
    
    try:
        stats = db.get_system_statistics()
        
        print(f"👥 User Management:")
        print(f"   Total Users: {stats['total_users']}")
        print(f"   Admin Users: {stats['admin_users']}")
        print(f"   Locked Accounts: {stats['locked_accounts']}")
        print(f"   Recent Registrations (30 days): {stats['recent_registrations']}")
        
        print(f"\n🔑 Key Management:")
        print(f"   Total RSA Key Pairs: {stats['total_keys']}")
        print(f"   Valid Keys: {stats['valid_keys']}")
        print(f"   Expired Keys: {stats['expired_keys']}")
        print(f"   Imported Public Keys: {stats['imported_keys']}")
        
        # Log admin dashboard access
        security_logger.log_activity(
            user_id=user_session.user_info['id'],
            action='admin_dashboard_view',
            status='success',
            details='Admin viewed system dashboard'
        )
        
    except Exception as e:
        print(f"❌ Error loading dashboard: {e}")
        security_logger.log_activity(
            user_id=user_session.user_info['id'],
            action='admin_dashboard_view',
            status='failure',
            details=f'Admin dashboard error: {e}'
        )
    
    input("\nPress Enter to continue...")

@admin_required
def handle_user_account_management():
    """User account management interface"""
    while True:
        print("\n=== USER ACCOUNT MANAGEMENT ===")
        print("👥 Account Administration")
        print("-" * 35)
        print("1. List All User Accounts")
        print("2. View User Details")
        print("3. Lock User Account")
        print("4. Unlock User Account")
        print("5. Delete User Account")
        print("6. Back to Admin Panel")
        print("-" * 35)
        
        choice = input("\nSelect an option: ").strip()
        
        if choice == "1":
            handle_list_all_users()
        elif choice == "2":
            handle_view_user_details()
        elif choice == "3":
            handle_lock_user_account()
        elif choice == "4":
            handle_unlock_user_account()
        elif choice == "5":
            handle_delete_user_account()
        elif choice == "6":
            break
        else:
            print("Invalid option. Please try again.")

@admin_required
def handle_list_all_users():
    """Display all user accounts"""
    print("\n=== ALL USER ACCOUNTS ===")
    
    try:
        users = db.get_all_users_for_admin()
        
        if not users:
            print("No users found.")
            input("\nPress Enter to continue...")
            return
        
        print(f"\nFound {len(users)} user(s):\n")
        print(f"{'ID':<4} {'Email':<25} {'Name':<20} {'Role':<6} {'Status':<10} {'Created':<12}")
        print("-" * 85)
        
        for user in users:
            status = "🔒 Locked" if user['is_locked'] else "✅ Active"
            created = safe_strftime(user['created_at'], '%Y-%m-%d')
            
            print(f"{user['id']:<4} {user['email']:<25} {user['name'][:19]:<20} "
                  f"{user['role']:<6} {status:<10} {created:<12}")
        
        # Log admin action
        security_logger.log_activity(
            user_id=user_session.user_info['id'],
            action='admin_list_users',
            status='success',
            details=f'Admin viewed user list ({len(users)} users)'
        )
        
    except Exception as e:
        print(f"❌ Error loading users: {e}")
        security_logger.log_activity(
            user_id=user_session.user_info['id'],
            action='admin_list_users',
            status='failure',
            details=f'Admin user list error: {e}'
        )
    
    input("\nPress Enter to continue...")

@admin_required
def handle_view_user_details():
    """View detailed information for a specific user"""
    print("\n=== VIEW USER DETAILS ===")
    
    try:
        user_id = input("Enter User ID: ").strip()
        if not user_id.isdigit():
            print("Invalid User ID. Please enter a number.")
            input("Press Enter to continue...")
            return
        
        user = db.get_user_details_for_admin(int(user_id))
        if not user:
            print(f"User with ID {user_id} not found.")
            input("Press Enter to continue...")
            return
        
        print(f"\n📋 User Details:")
        print(f"   ID: {user['id']}")
        print(f"   Email: {user['email']}")
        print(f"   Name: {user['name']}")
        print(f"   Phone: {user['phone'] or 'Not provided'}")
        print(f"   Address: {user['address'] or 'Not provided'}")
        print(f"   Birth Date: {user['birth_date'] or 'Not provided'}")
        print(f"   Role: {user['role']}")
        print(f"   Account Status: {'🔒 Locked' if user['is_locked'] else '✅ Active'}")
        print(f"   Failed Attempts: {user['failed_attempts']}")
        print(f"   Locked Until: {user['locked_until'] or 'Not locked'}")
        print(f"   Created: {user['created_at']}")
        
        # Log admin action
        security_logger.log_activity(
            user_id=user_session.user_info['id'],
            action='admin_view_user_details',
            status='success',
            details=f'Admin viewed details for user {user["email"]} (ID: {user_id})'
        )
        
    except Exception as e:
        print(f"❌ Error loading user details: {e}")
        security_logger.log_activity(
            user_id=user_session.user_info['id'],
            action='admin_view_user_details',
            status='failure',
            details=f'Admin user details error: {e}'
        )
    
    input("\nPress Enter to continue...")

@admin_required
def handle_lock_user_account():
    """Lock a user account"""
    print("\n=== LOCK USER ACCOUNT ===")
    
    try:
        user_id = input("Enter User ID to lock: ").strip()
        if not user_id.isdigit():
            print("Invalid User ID. Please enter a number.")
            input("Press Enter to continue...")
            return
        
        user_id = int(user_id)
        
        # Check if user exists and get details
        user = db.get_user_details_for_admin(user_id)
        if not user:
            print(f"User with ID {user_id} not found.")
            input("Press Enter to continue...")
            return
        
        # Prevent self-locking
        if user_id == user_session.user_info['id']:
            print("❌ You cannot lock your own account.")
            input("Press Enter to continue...")
            return
        
        if user['is_locked']:
            print(f"User {user['email']} is already locked.")
            input("Press Enter to continue...")
            return
        
        # Confirm action
        print(f"⚠️ About to lock account: {user['email']} (ID: {user_id})")
        confirm = input("Are you sure? (yes/no): ").strip().lower()
        
        if confirm == 'yes':
            result = db.admin_lock_user_account(user_id, user_session.user_info['id'])
            if result:
                print(f"✅ Account {user['email']} has been locked successfully.")
            else:
                print("❌ Failed to lock account.")
        else:
            print("Account lock cancelled.")
        
    except Exception as e:
        print(f"❌ Error locking account: {e}")
        security_logger.log_activity(
            user_id=user_session.user_info['id'],
            action='admin_lock_account',
            status='failure',
            details=f'Admin account lock error: {e}'
        )
    
    input("Press Enter to continue...")

@admin_required
def handle_unlock_user_account():
    """Unlock a user account"""
    print("\n=== UNLOCK USER ACCOUNT ===")
    
    try:
        user_id = input("Enter User ID to unlock: ").strip()
        if not user_id.isdigit():
            print("Invalid User ID. Please enter a number.")
            input("Press Enter to continue...")
            return
        
        user_id = int(user_id)
        
        # Check if user exists and get details
        user = db.get_user_details_for_admin(user_id)
        if not user:
            print(f"User with ID {user_id} not found.")
            input("Press Enter to continue...")
            return
        
        if not user['is_locked']:
            print(f"User {user['email']} is not locked.")
            input("Press Enter to continue...")
            return
        
        # Confirm action
        print(f"🔓 About to unlock account: {user['email']} (ID: {user_id})")
        confirm = input("Are you sure? (yes/no): ").strip().lower()
        
        if confirm == 'yes':
            result = db.admin_unlock_user_account(user_id, user_session.user_info['id'])
            if result:
                print(f"✅ Account {user['email']} has been unlocked successfully.")
            else:
                print("❌ Failed to unlock account.")
        else:
            print("Account unlock cancelled.")
        
    except Exception as e:
        print(f"❌ Error unlocking account: {e}")
        security_logger.log_activity(
            user_id=user_session.user_info['id'],
            action='admin_unlock_account',
            status='failure',
            details=f'Admin account unlock error: {e}'
        )
    
    input("Press Enter to continue...")

@admin_required
def handle_delete_user_account():
    """Delete a user account (dangerous operation)"""
    print("\n=== DELETE USER ACCOUNT ===")
    print("⚠️  WARNING: This action is IRREVERSIBLE!")
    print("⚠️  All user data, keys, and logs will be permanently deleted!")
    
    try:
        user_id = input("Enter User ID to delete: ").strip()
        if not user_id.isdigit():
            print("Invalid User ID. Please enter a number.")
            input("Press Enter to continue...")
            return
        
        user_id = int(user_id)
        
        # Check if user exists and get details
        user = db.get_user_details_for_admin(user_id)
        if not user:
            print(f"User with ID {user_id} not found.")
            input("Press Enter to continue...")
            return
        
        # Prevent self-deletion
        if user_id == user_session.user_info['id']:
            print("❌ You cannot delete your own account.")
            input("Press Enter to continue...")
            return
        
        # Multiple confirmations for safety
        print(f"🗑️ About to PERMANENTLY DELETE: {user['email']} (ID: {user_id})")
        print("⚠️ This will delete ALL user data including:")
        print("   - User profile and credentials")
        print("   - RSA key pairs")
        print("   - Activity logs")
        print("   - Imported public keys")
        
        confirm1 = input("\nType 'DELETE' to confirm: ").strip()
        if confirm1 != 'DELETE':
            print("Account deletion cancelled.")
            input("Press Enter to continue...")
            return
        
        confirm2 = input(f"Type the user email '{user['email']}' to confirm: ").strip()
        if confirm2 != user['email']:
            print("Account deletion cancelled.")
            input("Press Enter to continue...")
            return
        
        result = db.admin_delete_user_account(user_id, user_session.user_info['id'])
        if result:
            print(f"✅ Account {user['email']} has been permanently deleted.")
        else:
            print("❌ Failed to delete account.")
        
    except Exception as e:
        print(f"❌ Error deleting account: {e}")
        security_logger.log_activity(
            user_id=user_session.user_info['id'],
            action='admin_delete_account',
            status='failure',
            details=f'Admin account deletion error: {e}'
        )
    
    input("Press Enter to continue...")

@admin_required
def handle_system_logs_viewing():
    """View system-wide activity logs"""
    while True:
        print("\n=== SYSTEM ACTIVITY LOGS ===")
        print("📜 Log Management")
        print("-" * 25)
        print("1. View Recent Logs (Last 50)")
        print("2. View All Logs (Last 100)")
        print("3. Filter Logs by User")
        print("4. Filter Logs by Action")
        print("5. Back to Admin Panel")
        print("-" * 25)
        
        choice = input("\nSelect an option: ").strip()
        
        if choice == "1":
            handle_view_recent_logs(50)
        elif choice == "2":
            handle_view_recent_logs(100)
        elif choice == "3":
            handle_filter_logs_by_user()
        elif choice == "4":
            handle_filter_logs_by_action()
        elif choice == "5":
            break
        else:
            print("Invalid option. Please try again.")

@admin_required
def handle_view_recent_logs(limit=50):
    """Display recent system logs"""
    print(f"\n=== RECENT SYSTEM LOGS (Last {limit}) ===")
    
    try:
        logs = db.get_system_activity_logs(limit=limit)
        
        if not logs:
            print("No logs found.")
            input("\nPress Enter to continue...")
            return
        
        print(f"\nShowing {len(logs)} log entries:\n")
        print(f"{'Time':<19} {'User':<25} {'Action':<20} {'Status':<8} {'Details'}")
        print("-" * 100)
        
        for log in logs:
            timestamp = safe_strftime(log['created_at'], '%Y-%m-%d %H:%M:%S')
            user_email = log['user_email'][:24] if log['user_email'] else 'System'
            action = log['action'][:19] if log['action'] else 'N/A'
            status = log['status']
            details = log['details'][:30] + '...' if log['details'] and len(log['details']) > 30 else (log['details'] or '')
            
            print(f"{timestamp:<19} {user_email:<25} {action:<20} {status:<8} {details}")
        
        # Log admin action
        security_logger.log_activity(
            user_id=user_session.user_info['id'],
            action='admin_view_logs',
            status='success',
            details=f'Admin viewed system logs (limit: {limit})'
        )
        
    except Exception as e:
        print(f"❌ Error loading logs: {e}")
        security_logger.log_activity(
            user_id=user_session.user_info['id'],
            action='admin_view_logs',
            status='failure',
            details=f'Admin log viewing error: {e}'
        )
    
    input("\nPress Enter to continue...")

@admin_required
def handle_filter_logs_by_user():
    """Filter and display logs by specific user"""
    print("\n=== FILTER LOGS BY USER ===")
    
    try:
        user_id = input("Enter User ID to filter logs: ").strip()
        if not user_id.isdigit():
            print("Invalid User ID. Please enter a number.")
            input("Press Enter to continue...")
            return
        
        logs = db.get_system_activity_logs(limit=100, user_filter=int(user_id))
        
        if not logs:
            print(f"No logs found for User ID {user_id}.")
            input("\nPress Enter to continue...")
            return
        
        print(f"\nShowing {len(logs)} log entries for User ID {user_id}:\n")
        print(f"{'Time':<19} {'Action':<25} {'Status':<8} {'Details'}")
        print("-" * 80)
        
        for log in logs:
            timestamp = safe_strftime(log['created_at'], '%Y-%m-%d %H:%M:%S')
            action = log['action'][:24] if log['action'] else 'N/A'
            status = log['status']
            details = log['details'][:35] + '...' if log['details'] and len(log['details']) > 35 else (log['details'] or '')
            
            print(f"{timestamp:<19} {action:<25} {status:<8} {details}")
        
        # Log admin action
        security_logger.log_activity(
            user_id=user_session.user_info['id'],
            action='admin_filter_logs_user',
            status='success',
            details=f'Admin filtered logs by User ID {user_id}'
        )
        
    except Exception as e:
        print(f"❌ Error filtering logs: {e}")
        security_logger.log_activity(
            user_id=user_session.user_info['id'],
            action='admin_filter_logs_user',
            status='failure',
            details=f'Admin log filtering error: {e}'
        )
    
    input("\nPress Enter to continue...")

@admin_required
def handle_filter_logs_by_action():
    """Filter and display logs by action type"""
    print("\n=== FILTER LOGS BY ACTION ===")
    
    try:
        action_filter = input("Enter action keyword to filter (e.g., 'login', 'admin', 'encrypt'): ").strip()
        if not action_filter:
            print("Action filter cannot be empty.")
            input("Press Enter to continue...")
            return
        
        logs = db.get_system_activity_logs(limit=100, action_filter=action_filter)
        
        if not logs:
            print(f"No logs found containing action '{action_filter}'.")
            input("\nPress Enter to continue...")
            return
        
        print(f"\nShowing {len(logs)} log entries containing '{action_filter}':\n")
        print(f"{'Time':<19} {'User':<25} {'Action':<20} {'Status':<8} {'Details'}")
        print("-" * 100)
        
        for log in logs:
            timestamp = safe_strftime(log['created_at'], '%Y-%m-%d %H:%M:%S')
            user_email = log['user_email'][:24] if log['user_email'] else 'System'
            action = log['action'][:19] if log['action'] else 'N/A'
            status = log['status']
            details = log['details'][:30] + '...' if log['details'] and len(log['details']) > 30 else (log['details'] or '')
            
            print(f"{timestamp:<19} {user_email:<25} {action:<20} {status:<8} {details}")
        
        # Log admin action
        security_logger.log_activity(
            user_id=user_session.user_info['id'],
            action='admin_filter_logs_action',
            status='success',
            details=f'Admin filtered logs by action: {action_filter}'
        )
        
    except Exception as e:
        print(f"❌ Error filtering logs: {e}")
        security_logger.log_activity(
            user_id=user_session.user_info['id'],
            action='admin_filter_logs_action',
            status='failure',
            details=f'Admin log filtering error: {e}'
        )
    
    input("\nPress Enter to continue...")

@admin_required
def handle_user_role_management():
    """Manage user roles"""
    print("\n=== USER ROLE MANAGEMENT ===")
    
    try:
        user_id = input("Enter User ID to manage role: ").strip()
        if not user_id.isdigit():
            print("Invalid User ID. Please enter a number.")
            input("Press Enter to continue...")
            return
        
        user_id = int(user_id)
        
        # Check if user exists
        user = db.get_user_details_for_admin(user_id)
        if not user:
            print(f"User with ID {user_id} not found.")
            input("Press Enter to continue...")
            return
        
        # Prevent self-role change
        if user_id == user_session.user_info['id']:
            print("❌ You cannot change your own role.")
            input("Press Enter to continue...")
            return
        
        print(f"\n👤 User: {user['email']}")
        print(f"Current Role: {user['role']}")
        print("\nAvailable Roles:")
        print("1. admin - Full system access")
        print("2. user - Standard user access")
        
        new_role_choice = input("\nSelect new role (1-2): ").strip()
        
        if new_role_choice == "1":
            new_role = "admin"
        elif new_role_choice == "2":
            new_role = "user"
        else:
            print("Invalid choice.")
            input("Press Enter to continue...")
            return
        
        if new_role == user['role']:
            print(f"User already has role '{new_role}'.")
            input("Press Enter to continue...")
            return
        
        # Confirm role change
        print(f"\n⚠️ About to change role for {user['email']} from '{user['role']}' to '{new_role}'")
        confirm = input("Are you sure? (yes/no): ").strip().lower()
        
        if confirm == 'yes':
            result = db.update_user_role(user_id, new_role, user_session.user_info['id'])
            if result:
                print(f"✅ Role for {user['email']} changed to '{new_role}' successfully.")
            else:
                print("❌ Failed to update user role.")
        else:
            print("Role change cancelled.")
        
    except Exception as e:
        print(f"❌ Error managing user role: {e}")
        security_logger.log_activity(
            user_id=user_session.user_info['id'],
            action='admin_update_role',
            status='failure',
            details=f'Admin role management error: {e}'
        )
    
    input("Press Enter to continue...")

def handle_qr_operations(user_email, db, logger):
    """Handle QR code operations submenu"""
    while True:
        show_qr_code_menu()
        choice = input("\nSelect an option: ").strip()
        
        if choice == "1":
            handle_generate_qr_code()
        elif choice == "2":
            handle_import_qr_code()
        elif choice == "3":
            handle_list_imported_keys()
        elif choice == "4":
            handle_search_public_key()
        elif choice == "5":
            break
        else:
            print("Invalid option. Please try again.")

def handle_key_status_and_management(user_email, key_manager, db, logger):
    """Handle key status and management submenu"""
    while True:
        show_key_management_menu()
        choice = input("\nSelect an option: ").strip()
        
        if choice == "1":
            handle_key_status()
        elif choice == "2":
            handle_generate_keys()
        elif choice == "3":
            handle_renew_keys()
        elif choice == "4":
            handle_key_security_info()
        elif choice == "5":
            break
        else:
            print("Invalid option. Please try again.")

def handle_update_account_information(user_email, db, logger):
    """Handle account information updates submenu"""
    while True:
        show_account_menu()
        choice = input("\nSelect an option: ").strip()
        
        if choice == "1":
            handle_profile_update()
        elif choice == "2":
            handle_passphrase_change()
        elif choice == "3":
            handle_view_account_status()
        elif choice == "4":
            break
        else:
            print("Invalid option. Please try again.")

def handle_file_encryption_operations(user_email, key_manager, db, logger):
    """Handle file encryption operations submenu"""
    while True:
        show_file_encryption_menu()
        choice = input("\nSelect an option: ").strip()
        
        if choice == "1":
            handle_encrypt_file()
        elif choice == "2":
            handle_decrypt_file()
        elif choice == "3":
            handle_list_recipients()
        elif choice == "4":
            break
        else:
            print("Invalid option. Please try again.")

def handle_account_recovery():
    """Handle account recovery using recovery code"""
    print("\n🔐 ACCOUNT RECOVERY")
    print("-" * 30)
    print("Use your recovery code to reset your passphrase.")
    print("⚠️  Warning: This will invalidate your existing RSA keys.")
    print("   You will need to generate new keys after recovery.")
    print("-" * 30)
    
    try:
        email = input("Email: ").strip()
        
        if not email:
            print("❌ Email is required.")
            input("\nPress Enter to continue...")
            return
        
        print("\nEnter your 16-character recovery code:")
        print("(This was provided when you registered your account)")
        recovery_code = input("Recovery Code: ").strip()
        
        if not recovery_code:
            print("❌ Recovery code is required.")
            input("\nPress Enter to continue...")
            return
        
        if len(recovery_code) != 16:
            print("❌ Recovery code must be 16 characters long.")
            input("\nPress Enter to continue...")
            return
        
        print("\nEnter your new passphrase:")
        new_passphrase = getpass.getpass("New Passphrase: ")
        confirm_passphrase = getpass.getpass("Confirm New Passphrase: ")
        
        if new_passphrase != confirm_passphrase:
            print("❌ Passphrases do not match!")
            input("\nPress Enter to continue...")
            return
        
        print("\n🔄 Processing account recovery...")
        success, message = auth_manager.recover_account_with_code(
            email, recovery_code, new_passphrase
        )
        
        if success:
            print(f"✅ {message}")
            print("\n📋 Next Steps:")
            print("1. Login with your new passphrase")
            print("2. Generate new RSA keys for encryption")
            print("3. Export your new public key via QR code")
        else:
            print(f"❌ Recovery failed: {message}")
        
        input("\nPress Enter to continue...")
    
    except Exception as e:
        print(f"❌ Recovery error: {str(e)}")
        input("\nPress Enter to continue...")

def main():
    """Main application function"""
    try:
        if not initialize_application():
            print("Application initialization failed. Exiting.")
            sys.exit(1)
        
        show_welcome()
        
        # Main application loop
        while True:
            if not user_session.is_fully_authenticated():
                # Show public menu
                show_main_menu()
                choice = input("Choose an option (1-4): ").strip()
                
                if choice == "1":
                    handle_user_registration()
                elif choice == "2":
                    handle_user_login()
                elif choice == "3":
                    handle_account_recovery()
                elif choice == "4":
                    print("\n👋 Thank you for using Security Application!")
                    security_logger.log_activity(action='app_shutdown', status='success', details='Normal exit')
                    break
                else:
                    print("❌ Invalid choice. Please try again.")
                    input("Press Enter to continue...")
            
            else:
                # Show authenticated menu
                handle_authenticated_user(user_session.user_info['email'])
        
    except KeyboardInterrupt:
        print("\n\nApplication interrupted by user")
        if user_session.is_authenticated:
            security_logger.log_activity(action='app_interrupt', status='success', 
                                       details=f"User {user_session.user_info['email']} interrupted")
        else:
            security_logger.log_activity(action='app_interrupt', status='success', details='User interrupt')
    except Exception as e:
        print(f"❌ GUI Application error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    # Use GUI by default, CLI available as fallback
    import sys
    
    if '--cli' in sys.argv:
        # Run CLI version
        main()
    else:
        # Run GUI version
        from gui.app import main as gui_main
        gui_main() 