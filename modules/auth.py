import hashlib
import secrets
import re
import hmac
import pyotp
import qrcode
import os
from modules.database import db_manager
from modules.logger import log_auth_success, log_auth_failure, log_registration, log_error, security_logger
from datetime import datetime, timedelta

class AuthManager:
    EMAIL_REGEX = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    PASSWORD_REGEX = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^a-zA-Z\d]).{8,}$"
    
    @staticmethod
    def validate_email(email):
        if not email or not email.strip():
            return False, "Email is required"
        if not re.match(AuthManager.EMAIL_REGEX, email.strip()):
            return False, "Invalid email format"
        return True, "Valid email"
    
    @staticmethod
    def validate_password(password):
        if not password:
            return False, "Password is required"
        if len(password) < 8:
            return False, "Password must be at least 8 characters"
        if not re.search(r"[a-z]", password):
            return False, "Password must contain lowercase letters"
        if not re.search(r"[A-Z]", password):
            return False, "Password must contain uppercase letters"
        if not re.search(r"\d", password):
            return False, "Password must contain numbers"
        if not re.search(r"[^a-zA-Z\d]", password):
            return False, "Password must contain symbols"
        return True, "Strong password"
    
    @staticmethod
    def validate_name(name):
        if not name or not name.strip():
            return False, "Name is required"
        if len(name.strip()) < 2:
            return False, "Name must be at least 2 characters"
        return True, "Valid name"
    
    @staticmethod
    def hash_password(password):
        salt = secrets.token_bytes(32)
        pwd_hash = hashlib.sha256(salt + password.encode('utf-8')).digest()
        return salt, pwd_hash
    
    @staticmethod
    def verify_password(password, salt, stored_hash):
        try:
            if isinstance(salt, str):
                salt = bytes.fromhex(salt)
            if isinstance(stored_hash, str):
                stored_hash = bytes.fromhex(stored_hash)
            
            new_hash = hashlib.sha256(salt + password.encode('utf-8')).digest()
            return hmac.compare_digest(new_hash, stored_hash)
        except Exception:
            return False
    
    @staticmethod
    def register_user(email, name, password, phone=None, address=None, birth_date=None):
        email = email.strip()
        name = name.strip()
        
        # Validate email
        email_valid, email_msg = AuthManager.validate_email(email)
        if not email_valid:
            log_error(email, "VALIDATION", f"Email validation failed: {email_msg}")
            return False, email_msg
        
        # Validate name
        name_valid, name_msg = AuthManager.validate_name(name)
        if not name_valid:
            log_error(email, "VALIDATION", f"Name validation failed: {name_msg}")
            return False, name_msg
        
        # Validate password
        pwd_valid, pwd_msg = AuthManager.validate_password(password)
        if not pwd_valid:
            log_error(email, "VALIDATION", "Password validation failed")
            return False, pwd_msg
        
        # Check if user already exists
        if db_manager.user_exists(email):
            log_error(email, "REGISTRATION", "Attempted registration with existing email")
            return False, "Email already registered"
        
        # Hash password
        salt, password_hash = AuthManager.hash_password(password)
        
        # Create user
        success = db_manager.create_user(email, name, password_hash, salt, phone, address, birth_date)
        if success:
            log_registration(email, f"User registered successfully: name={name}")
            return True, "Registration successful"
        else:
            log_error(email, "REGISTRATION", "Database error during user creation")
            return False, "Registration failed. Please try again."
    
    @staticmethod
    def login_user(email, password):
        try:
            if not email or not password:
                return False, "Email and password are required", None
            
            email = email.strip()
            user_data = db_manager.get_user_by_email(email)
            if not user_data:
                log_auth_failure(email, "User not found")
                return False, "Invalid credentials", None
            
            stored_salt = user_data[4]  # salt column
            stored_hash = user_data[3]  # password_hash column
            
            if AuthManager.verify_password(password, stored_salt, stored_hash):
                log_auth_success(email, "Login successful")
                # Convert tuple to dictionary for better usability
                user_dict = {
                    'id': user_data[0],
                    'email': user_data[1],
                    'name': user_data[2],
                    'role': user_data[8] if len(user_data) > 8 else 'user'
                }
                return True, "Login successful", user_dict
            else:
                log_auth_failure(email, "Invalid password")
                return False, "Invalid credentials", None
                
        except Exception as e:
            log_error("LOGIN", f"Login failed for {email}: {str(e)}")
            return False, "Login failed due to system error", None

def generate_otp():
    """Generate a secure 6-digit OTP using cryptographically secure random numbers"""
    return str(secrets.randbelow(10**6)).zfill(6)

def send_otp_email(user_email, otp_code, expiry_minutes=5):
    """Simulate email delivery with console output"""
    expiry_time = (datetime.now() + timedelta(minutes=expiry_minutes)).strftime("%H:%M:%S")
    
    print("\n" + "="*60)
    print("                   📧 EMAIL NOTIFICATION")
    print("="*60)
    print(f"TO: {user_email}")
    print(f"FROM: security@securityapp.com")
    print(f"SUBJECT: Your Security Code")
    print("-"*60)
    print(f"")
    print(f"Your 6-digit security code is:")
    print(f"")
    print(f"           🔐 {otp_code} 🔐")
    print(f"")
    print(f"This code expires at {expiry_time} ({expiry_minutes} minutes)")
    print(f"Do not share this code with anyone.")
    print(f"")
    print("="*60)
    print()

def request_otp_for_user(user_id):
    """Generate and store OTP for user"""
    try:
        user = db_manager.get_user_by_id(user_id)
        if not user:
            security_logger.warning(f"OTP_REQUEST", "FAILED", f"User not found: {user_id}")
            return False
        
        # Cleanup expired OTPs first
        db_manager.cleanup_expired_otps()
        
        # Generate new OTP
        otp_code = generate_otp()
        expires_at = datetime.now() + timedelta(minutes=5)
        
        # Store OTP in database
        if db_manager.create_otp_code(user_id, otp_code, expires_at):
            # Simulate email delivery
            send_otp_email(user['email'], otp_code)
            security_logger.info(user['email'], "OTP_GENERATED", "SUCCESS", f"OTP sent to {user['email']}")
            return True
        else:
            security_logger.error(user['email'], "OTP_STORAGE", "FAILED", "Failed to store OTP in database")
            return False
            
    except Exception as e:
        security_logger.error("UNKNOWN", "OTP_REQUEST", "ERROR", f"Exception: {str(e)}")
        return False

def verify_otp_for_user(user_id, otp_code):
    """Verify OTP code for user"""
    try:
        user = db_manager.get_user_by_id(user_id)
        if not user:
            security_logger.warning(f"OTP_VERIFY", "FAILED", f"User not found: {user_id}")
            return False
        
        # Validate OTP format
        if not otp_code or not otp_code.isdigit() or len(otp_code) != 6:
            security_logger.warning(user['email'], "OTP_VERIFY", "FAILED", "Invalid OTP format")
            return False
        
        # Verify OTP against database
        if db_manager.validate_otp_code(user_id, otp_code):
            security_logger.info(user['email'], "OTP_VERIFY", "SUCCESS", "OTP verified successfully")
            return True
        else:
            security_logger.warning(user['email'], "OTP_VERIFY", "FAILED", "Invalid or expired OTP")
            return False
            
    except Exception as e:
        security_logger.error("UNKNOWN", "OTP_VERIFY", "ERROR", f"Exception: {str(e)}")
        return False

def generate_totp_secret():
    """Generate a cryptographically secure TOTP secret"""
    return pyotp.random_base32()

def generate_qr_code_uri(email, secret):
    """Generate QR code provisioning URI for Google Authenticator"""
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=email, issuer_name="SecurityApp")

def verify_totp_code(secret, code):
    """Verify TOTP code against stored secret"""
    try:
        if not secret or not code:
            return False
        
        if not code.isdigit() or len(code) != 6:
            return False
        
        totp = pyotp.TOTP(secret)
        return totp.verify(code, valid_window=1)
        
    except Exception:
        return False

def setup_totp_for_user(user_id):
    """Generate TOTP secret and setup for user"""
    try:
        user = db_manager.get_user_by_id(user_id)
        if not user:
            security_logger.warning("TOTP_SETUP", "FAILED", f"User not found: {user_id}")
            return False, None, None
        
        # Generate new TOTP secret
        secret = generate_totp_secret()
        
        # Store secret in database
        if db_manager.update_user_totp_secret(user_id, secret):
            # Generate QR code URI
            qr_uri = generate_qr_code_uri(user['email'], secret)
            
            # Generate QR code image
            qr_filename = f"totp_{user['email'].replace('@', '_').replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
            qr_path = os.path.join("data", "qr_codes", qr_filename)
            
            # Ensure directory exists
            os.makedirs(os.path.dirname(qr_path), exist_ok=True)
            
            # Generate and save QR code
            qr_img = qrcode.make(qr_uri)
            qr_img.save(qr_path)
            
            security_logger.info(user['email'], "TOTP_SETUP", "SUCCESS", f"TOTP secret generated and QR code saved: {qr_filename}")
            return True, qr_path, secret
        else:
            security_logger.error(user['email'], "TOTP_SETUP", "FAILED", "Failed to store TOTP secret in database")
            return False, None, None
            
    except Exception as e:
        security_logger.error("UNKNOWN", "TOTP_SETUP", "ERROR", f"Exception: {str(e)}")
        return False, None, None

def verify_totp_for_user(user_id, totp_code):
    """Verify TOTP code for user"""
    try:
        user = db_manager.get_user_by_id(user_id)
        if not user:
            security_logger.warning("TOTP_VERIFY", "FAILED", f"User not found: {user_id}")
            return False
        
        # Get user's TOTP secret
        secret = db_manager.get_user_totp_secret(user_id)
        if not secret:
            security_logger.warning(user['email'], "TOTP_VERIFY", "FAILED", "No TOTP secret found for user")
            return False
        
        # Verify TOTP code
        if verify_totp_code(secret, totp_code):
            security_logger.info(user['email'], "TOTP_VERIFY", "SUCCESS", "TOTP verified successfully")
            return True
        else:
            security_logger.warning(user['email'], "TOTP_VERIFY", "FAILED", "Invalid TOTP code")
            return False
            
    except Exception as e:
        security_logger.error("UNKNOWN", "TOTP_VERIFY", "ERROR", f"Exception: {str(e)}")
        return False

auth_manager = AuthManager() 