import hashlib
import secrets
import re
import time
from datetime import datetime, timedelta
from typing import Dict, Tuple, Optional, Union
from .database import DatabaseManager
from .logger import SecurityLogger
from .key_manager import KeyManager
import json

class GlobalUserSession:
    """Singleton class to track the current logged-in user globally"""
    _instance = None
    _current_user = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(GlobalUserSession, cls).__new__(cls)
        return cls._instance
    
    def set_current_user(self, user_info: Dict):
        """Set the current logged-in user"""
        self._current_user = user_info.copy() if user_info else None
    
    def get_current_user(self) -> Optional[Dict]:
        """Get the current logged-in user info"""
        return self._current_user.copy() if self._current_user else None
    
    def get_current_user_email(self) -> Optional[str]:
        """Get the current user's email for logging"""
        return self._current_user.get('email') if self._current_user else None
    
    def get_current_user_id(self) -> Optional[int]:
        """Get the current user's ID"""
        return self._current_user.get('id') if self._current_user else None
    
    def get_current_user_name(self) -> Optional[str]:
        """Get the current user's name"""
        return self._current_user.get('name') if self._current_user else None
    
    def is_logged_in(self) -> bool:
        """Check if a user is currently logged in"""
        return self._current_user is not None
    
    def clear_current_user(self):
        """Clear the current user session"""
        self._current_user = None
    
    def __str__(self):
        if self._current_user:
            return f"User: {self._current_user.get('name')} ({self._current_user.get('email')})"
        return "No user logged in"

# Global instance
global_user_session = GlobalUserSession()

class AuthManager:
    def __init__(self):
        self.db = DatabaseManager()
        self.logger = SecurityLogger()
        self.key_manager = KeyManager()
        self.password_pattern = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$')
        self.email_pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    
    def generate_salt(self) -> str:
        """Generate cryptographically secure salt"""
        return secrets.token_hex(32)
    
    def generate_recovery_code(self):
        """Generate 16-character recovery code"""
        return secrets.token_urlsafe(12)[:16].upper()
    
    def hash_password(self, password: str, salt: str) -> str:
        """Hash password with salt using SHA-256"""
        return hashlib.sha256((password + salt).encode()).hexdigest()
    
    def hash_recovery_code(self, recovery_code):
        """Hash recovery code for secure storage"""
        return hashlib.sha256(recovery_code.encode()).hexdigest()
    
    def validate_email(self, email: str) -> Tuple[bool, str]:
        """Validate email format"""
        if not email or len(email) > 255:
            return False, "Email must be 1-255 characters"
        
        if not self.email_pattern.match(email):
            return False, "Invalid email format"
        
        # Check if email already exists
        result = self.db.execute_query("SELECT id FROM users WHERE email = ?", (email,), fetch=True)
        if result:
            return False, "Email already registered"
        
        return True, "Valid email"
    
    def validate_password_strength(self, password: str) -> Tuple[bool, str]:
        """Validate password strength"""
        if not password:
            return False, "Password is required"
        
        if len(password) < 8:
            return False, "Password must be at least 8 characters"
        
        patterns = [
            (r'[A-Z]', "Password must contain at least one uppercase letter"),
            (r'[a-z]', "Password must contain at least one lowercase letter"),
            (r'\d', "Password must contain at least one number"),
            (r'[!@#$%^&*(),.?":{}|<>]', "Password must contain at least one special character")
        ]
        
        for pattern, message in patterns:
            if not re.search(pattern, password):
                return False, message
        
        return True, "Strong password"
    
    def validate_user_data(self, email, name, password, phone=None, address=None, birth_date=None):
        """Validate all user registration data"""
        errors = []
        
        # Validate email
        email_valid, email_msg = self.validate_email(email)
        if not email_valid:
            errors.append(email_msg)
        
        # Validate name
        if not name or len(name.strip()) < 2:
            errors.append("Name must be at least 2 characters")
        
        # Validate password
        pwd_valid, pwd_msg = self.validate_password_strength(password)
        if not pwd_valid:
            errors.append(pwd_msg)
        
        # Validate phone (optional)
        if phone and not re.match(r'^\+?[\d\s\-\(\)]{10,20}$', phone):
            errors.append("Invalid phone number format")
        
        # Validate birth_date (optional)
        if birth_date:
            try:
                if isinstance(birth_date, str):
                    datetime.strptime(birth_date, '%Y-%m-%d')
            except ValueError:
                errors.append("Invalid birth date format (use YYYY-MM-DD)")
        
        return len(errors) == 0, errors
    
    def register_user(self, email: str, name: str, password: str, 
                     phone: str = None, address: str = None, 
                     birth_date: str = None, generate_keys: bool = True) -> Tuple[bool, str]:
        """Register a new user with complete validation and automatic key generation"""
        user_id = None
        try:
            # Validate input data
            email_valid, email_msg = self.validate_email(email)
            if not email_valid:
                self.logger.log_activity(action="USER_REGISTRATION", status="failure", 
                                             details=f"Validation failed: {', '.join(email_msg) if isinstance(email_msg, list) else email_msg}", email=email)
                return False, email_msg[0] if isinstance(email_msg, list) else email_msg
            
            pwd_valid, pwd_msg = self.validate_password_strength(password)
            if not pwd_valid:
                self.logger.log_activity(action="USER_REGISTRATION", status="failure", 
                                             details=f"Validation failed: {pwd_msg}", email=email)
                return False, pwd_msg
            
            # Generate salt and hash password
            salt = self.generate_salt()
            password_hash = self.hash_password(password, salt)
            
            # Generate recovery code
            recovery_code = self.generate_recovery_code()
            recovery_code_hash = self.hash_recovery_code(recovery_code)
            
            # Create user in database - get user ID for key generation
            user_data = (email.lower().strip(), name.strip(), phone.strip() if phone else None,
                         address.strip() if address else None, birth_date, password_hash, salt, recovery_code_hash)
            query = """
                INSERT INTO users (email, name, phone, address, birth_date, 
                                 password_hash, salt, recovery_code_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """
            user_id = self.db.execute_query(query, user_data)
            
            if not user_id:
                raise Exception("Failed to create user record")
            
            # Generate RSA keys if requested
            if generate_keys:
                key_success, key_message, key_data = self.key_manager.create_user_keys(user_id, password)
                if not key_success:
                    # Rollback user creation if key generation fails
                    self.db.execute_query("DELETE FROM users WHERE id = ?", (user_id,))
                    self.logger.log_activity(action="USER_REGISTRATION", status="failure", 
                                                 details=f"Key generation failed, rolled back user: {email}", email=email)
                    return False, f"Registration failed: {key_message}"
                
                self.logger.log_activity(action="KEY_MANAGEMENT", status="success", 
                                             details=f"RSA keys generated for new user: {email}", email=email)
            
            # Log successful registration
            self.logger.log_activity(
                action="user_registration",
                status="success",
                details=f"New user registered successfully with {'keys' if generate_keys else 'no keys'}",
                email=email
            )
            
            if generate_keys:
                return True, f"Registration successful! Save this recovery code: {recovery_code}\nRSA keys generated and ready for use."
            else:
                return True, f"Registration successful! Save this recovery code: {recovery_code}"
        
        except Exception as e:
            # Rollback user creation if it was created but key generation failed
            if user_id:
                try:
                    self.db.execute_query("DELETE FROM users WHERE id = ?", (user_id,))
                except:
                    pass
                    
            self.logger.log_activity(
                action="user_registration",
                status="failure",
                details=f"Registration failed: {str(e)}",
                email=email
            )
            return False, f"Registration failed: {str(e)}"
    
    def check_account_lockout(self, email: str) -> Tuple[bool, str, int]:
        """Check if account is locked and return status with remaining time"""
        query = "SELECT failed_attempts, locked_until FROM users WHERE email = ?"
        result = self.db.execute_query(query, (email,), fetch=True)
        
        if not result:
            return False, "Account not found", 0
        
        failed_attempts, locked_until = result[0]['failed_attempts'], result[0]['locked_until']
        
        if locked_until:
            try:
                if isinstance(locked_until, str):
                    # Try parsing with microseconds first, then without
                    try:
                        locked_until_dt = datetime.strptime(locked_until, '%Y-%m-%d %H:%M:%S.%f')
                    except ValueError:
                        locked_until_dt = datetime.strptime(locked_until, '%Y-%m-%d %H:%M:%S')
                else:
                    locked_until_dt = locked_until
                
                current_time = datetime.now()
                
                if current_time < locked_until_dt:
                    remaining_seconds = int((locked_until_dt - current_time).total_seconds())
                    remaining_minutes = remaining_seconds // 60
                    remaining_seconds = remaining_seconds % 60
                    return True, f"Account locked. Try again in {remaining_minutes}m {remaining_seconds}s", remaining_seconds
                
                # Unlock account if lockout period has passed
                if current_time >= locked_until_dt:
                    self.db.execute_query(
                        "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE email = ?",
                        (email,)
                    )
            except (ValueError, TypeError) as e:
                # If datetime parsing fails, clear the lock
                self.db.execute_query(
                    "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE email = ?",
                    (email,)
                )
        
        return False, "Account not locked", 0

    def apply_progressive_delay(self, failed_attempts: int, gui_mode: bool = False):
        """Apply progressive delay based on failed attempts"""
        if failed_attempts > 0 and not gui_mode:
            delay_seconds = min(2 ** failed_attempts, 30)  # Max 30 seconds
            time.sleep(delay_seconds)

    def update_failed_attempts(self, email: str, success: bool):
        """Update failed login attempts and handle account locking"""
        if success:
            # Reset failed attempts on successful login
            query = "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE email = ?"
            self.db.execute_query(query, (email,))
        else:
            # Increment failed attempts
            query = "SELECT failed_attempts FROM users WHERE email = ?"
            result = self.db.execute_query(query, (email,), fetch=True)
            
            if result:
                current_attempts = result[0]['failed_attempts'] + 1
                
                if current_attempts >= 5:
                    # Lock account for 5 minutes
                    locked_until = datetime.now() + timedelta(minutes=5)
                    query = """
                    UPDATE users SET failed_attempts = ?, locked_until = ?
                    WHERE email = ?
                    """
                    self.db.execute_query(query, (current_attempts, locked_until, email))
                    
                    self.logger.log_activity(action="account_lockout", status="warning", 
                                           details=f"Account locked for 5 minutes: {email}", email=email)
                else:
                    query = "UPDATE users SET failed_attempts = ? WHERE email = ?"
                    self.db.execute_query(query, (current_attempts, email))

    def verify_login_credentials(self, email: str, password: str, gui_mode: bool = False) -> Tuple[bool, str, Optional[Dict]]:
        """Verify login credentials with comprehensive security checks"""
        
        # Check if account is locked FIRST
        is_locked, lock_message, remaining_time = self.check_account_lockout(email)
        if is_locked:
            self.logger.log_activity(action="LOGIN_ATTEMPT", status="warning", 
                                         details=f"Locked account login attempt: {email}", email=email)
            return False, lock_message, None
        
        # Get user data and failed attempts for progressive delay
        query = """
            SELECT id, email, name, password_hash, salt, role, failed_attempts, is_locked 
            FROM users WHERE email = ?
        """
        result = self.db.execute_query(query, (email,), fetch=True)
        
        if not result:
            # Apply delay even for non-existent users to prevent email enumeration
            self.apply_progressive_delay(1, gui_mode)
            self.logger.log_activity(action="LOGIN_ATTEMPT", status="failure", 
                                         details=f"Login attempt with non-existent email: {email}", email=email)
            return False, "Invalid credentials", None
        
        user_data = result[0]
        user_id = user_data['id']
        user_email = user_data['email'] 
        name = user_data['name']
        stored_hash = user_data['password_hash']
        salt = user_data['salt']
        role = user_data['role']
        failed_attempts = user_data['failed_attempts']
        is_locked = user_data['is_locked']
        
        # Check if account is administratively locked
        if is_locked:
            self.logger.log_activity(action="LOGIN_ATTEMPT", status="warning", 
                                         details=f"Administratively locked account login attempt: {email}", email=email)
            return False, "Account is locked. Please contact an administrator.", None
        
        # Apply progressive delay based on previous failed attempts
        self.apply_progressive_delay(failed_attempts, gui_mode)
        
        # Verify password
        provided_hash = self.hash_password(password, salt)
        password_valid = provided_hash == stored_hash
        
        # Update failed attempts
        self.update_failed_attempts(email, password_valid)
        
        if password_valid:
            self.logger.log_activity(action="LOGIN_ATTEMPT", status="success", 
                                         details=f"Successful login: {email}", email=user_email)
            
            # Check key status for the user
            key_status_success, key_status_msg, key_status = self.key_manager.check_key_status(user_id)
            
            user_info = {
                'id': user_id,
                'email': user_email,
                'name': name,
                'role': role,
                'key_status': key_status if key_status_success else None,
                'key_warning': None
            }
            
            # Add key status warnings if needed
            if key_status_success and key_status:
                if key_status['status'] == 'expiring':
                    user_info['key_warning'] = f"Your RSA keys will expire in {key_status['days_until_expiry']} days. Please renew them soon."
                elif key_status['status'] == 'expired':
                    user_info['key_warning'] = "Your RSA keys have expired. Please renew them to access cryptographic features."
            
            # DO NOT set global user session here - only set it after complete MFA verification
            # This prevents session persistence bugs where old user remains logged in
            
            return True, "Login successful", user_info
        else:
            self.logger.log_activity(action="LOGIN_ATTEMPT", status="failure", 
                                         details=f"Invalid password for user: {email}", email=email)
            
            # Show warning about remaining attempts
            remaining_attempts = 5 - (failed_attempts + 1)
            if remaining_attempts > 0:
                return False, f"Invalid credentials. {remaining_attempts} attempts remaining before account lockout.", None
            else:
                return False, "Invalid credentials", None

    def initiate_login_flow(self, email: str, password: str, gui_mode: bool = False) -> Tuple[bool, str, Optional[Dict]]:
        """Complete login flow with MFA integration"""
        
        # Step 1: Verify credentials
        credential_valid, message, user_info = self.verify_login_credentials(email, password, gui_mode)
        
        if not credential_valid:
            return False, message, None
        
        # Step 2: Credentials are valid, but user needs MFA
        self.logger.log_activity(action="LOGIN_FLOW", status="success", 
                                     details=f"Credentials verified for {email}, MFA required", email=user_info['email'])
        
        return True, "Credentials verified. Please complete MFA verification.", user_info

    def complete_login_with_mfa(self, user_info: Dict, mfa_token: str, 
                               mfa_type: str = "otp", skip_mfa_verification: bool = False) -> Tuple[bool, str]:
        """Complete login after MFA verification"""
        from .mfa import mfa_manager
        
        # Skip MFA verification if already done (e.g., by MFA screen)
        if skip_mfa_verification:
            # Set global user session only after successful MFA completion
            global_user_session.set_current_user(user_info)
            
            self.logger.log_activity(action="LOGIN_COMPLETE", status="success", 
                                         details=f"Login completed with MFA: {user_info['email']}", email=user_info['email'])
            return True, f"Login successful! Welcome {user_info['name']}"
        
        if mfa_type == "otp":
            # Verify OTP token
            valid, mfa_message = mfa_manager.verify_otp(user_info['id'], mfa_token)
        elif mfa_type == "totp":
            # Verify TOTP token using user-specific method
            valid, mfa_message = mfa_manager.verify_user_totp(user_info['id'], mfa_token)
        else:
            return False, "Invalid MFA type"
        
        if valid:
            # Set global user session only after successful MFA completion
            global_user_session.set_current_user(user_info)
            
            self.logger.log_activity(action="LOGIN_COMPLETE", status="success", 
                                         details=f"Login completed with MFA: {user_info['email']}", email=user_info['email'])
            return True, f"Login successful! Welcome {user_info['name']}"
        else:
            self.logger.log_activity(action="LOGIN_COMPLETE", status="failure", 
                                         details=f"MFA verification failed: {user_info['email']}", email=user_info['email'])
            return False, f"MFA verification failed: {mfa_message}"

    def get_account_status(self, email: str) -> Dict:
        """Get detailed account status information including key status"""
        query = """
            SELECT id, failed_attempts, locked_until, created_at, role 
            FROM users WHERE email = ?
        """
        result = self.db.execute_query(query, (email,), fetch=True)
        
        if not result:
            return {"exists": False}
        
        user_data = result[0]
        user_id = user_data['id']
        failed_attempts = user_data['failed_attempts']
        locked_until = user_data['locked_until']
        created_at = user_data['created_at']
        role = user_data['role']
        is_locked, lock_message, remaining_time = self.check_account_lockout(email)
        
        # Get key status
        key_status_success, key_status_msg, key_status = self.key_manager.check_key_status(user_id)
        
        status_info = {
            "exists": True,
            "user_id": user_id,
            "failed_attempts": failed_attempts,
            "is_locked": is_locked,
            "lock_message": lock_message,
            "remaining_lockout_time": remaining_time,
            "created_at": created_at,
            "role": role,
            "key_status": key_status if key_status_success else None,
            "key_status_message": key_status_msg
        }
        
        return status_info
    
    def update_user_profile(self, user_id: int, name: str = None, phone: str = None, 
                           address: str = None, birth_date: str = None) -> Tuple[bool, str]:
        """Update user profile information"""
        try:
            updates = []
            params = []
            
            if name:
                updates.append("name = ?")
                params.append(name.strip())
            
            if phone:
                # Validate phone format
                if not re.match(r'^\+?[\d\s\-\(\)]{10,20}$', phone):
                    return False, "Invalid phone number format"
                updates.append("phone = ?")
                params.append(phone.strip())
            
            if address:
                updates.append("address = ?")
                params.append(address.strip())
            
            if birth_date:
                try:
                    if isinstance(birth_date, str):
                        datetime.strptime(birth_date, '%Y-%m-%d')
                    updates.append("birth_date = ?")
                    params.append(birth_date)
                except ValueError:
                    return False, "Invalid birth date format (use YYYY-MM-DD)"
            
            if not updates:
                return False, "No valid updates provided"
            
            params.append(user_id)
            query = f"UPDATE users SET {', '.join(updates)} WHERE id = ?"
            
            self.db.execute_query(query, params)
            self.logger.log_activity(action="PROFILE_UPDATE", status="success", 
                                         details=f"Profile updated for user ID: {user_id}", email=self.db.get_user_email_by_id(user_id))
            
            return True, "Profile updated successfully"
            
        except Exception as e:
            self.logger.log_activity(action="PROFILE_UPDATE", status="error", 
                                         details=f"Profile update failed for user ID {user_id}: {str(e)}", email=self.db.get_user_email_by_id(user_id))
            return False, f"Profile update failed: {str(e)}"
    
    def change_passphrase(self, user_id: int, current_password: str, new_password: str) -> Tuple[bool, str]:
        """Change user passphrase with key re-encryption"""
        try:
            # Get current user data
            query = "SELECT email, password_hash, salt FROM users WHERE id = ?"
            result = self.db.execute_query(query, (user_id,), fetch=True)
            
            if not result:
                return False, "User not found"
            
            user_data = result[0]
            email = user_data['email']
            current_hash = user_data['password_hash']
            salt = user_data['salt']
            
            # Verify current password
            provided_hash = self.hash_password(current_password, salt)
            if provided_hash != current_hash:
                self.logger.log_activity(action="PASSPHRASE_CHANGE", status="failure", 
                                             details=f"Invalid current password for user: {email}", email=email)
                return False, "Current password is incorrect"
            
            # Validate new password strength
            pwd_valid, pwd_msg = self.validate_password_strength(new_password)
            if not pwd_valid:
                return False, pwd_msg
            
            # Generate new salt and hash
            new_salt = self.generate_salt()
            new_password_hash = self.hash_password(new_password, new_salt)
            
            # Get the user's most recent key record
            key_record = self.db.get_user_keys_by_id(user_id)
            
            # If a key exists and is valid, re-encrypt it
            if key_record and key_record['status'] in ['valid', 'expiring']:
                # Decrypt with old passphrase and re-encrypt with new
                old_encrypted_key_json = key_record['encrypted_private_key']
                
                try:
                    encrypted_key_dict = json.loads(old_encrypted_key_json)
                except json.JSONDecodeError:
                    return False, "Failed to parse encrypted key data. Invalid format."

                decrypt_success, decrypt_message, private_key_obj = self.key_manager.decrypt_private_key(
                    encrypted_key_dict, current_password
                )
                
                if not decrypt_success:
                    return False, f"Failed to decrypt existing keys: {decrypt_message}"
                
                # Re-encrypt with new passphrase
                encrypt_success, encrypt_message, new_encrypted_key_data = self.key_manager.encrypt_private_key(private_key_obj, new_password)

                if not encrypt_success:
                    return False, f"Failed to re-encrypt private key: {encrypt_message}"
                
                # Update key in database
                update_success = self.db.update_key_encrypted_private_key(
                    key_record['id'], json.dumps(new_encrypted_key_data)
                )
                
                if not update_success:
                    return False, f"Failed to update key in database for ID {key_record['id']}"
            
            # Update user password in the database
            query = "UPDATE users SET password_hash = ?, salt = ? WHERE id = ?"
            self.db.execute_query(query, (new_password_hash, new_salt, user_id))
            
            self.logger.log_activity(action="PASSPHRASE_CHANGE", status="success", 
                                         details=f"Passphrase changed for user: {email}", email=email)
            
            return True, "Passphrase changed successfully. All RSA keys have been re-encrypted."
            
        except Exception as e:
            self.logger.log_activity(action="PASSPHRASE_CHANGE", status="error", 
                                         details=f"Passphrase change failed for user ID {user_id}: {str(e)}", email=self.db.get_user_email_by_id(user_id))
            return False, f"Passphrase change failed: {str(e)}"
    
    def validate_user_passphrase(self, user_id: int, passphrase: str) -> Tuple[bool, str]:
        """Validate passphrase against user's account password"""
        try:
            query = "SELECT password_hash, salt FROM users WHERE id = ?"
            result = self.db.execute_query(query, (user_id,), fetch=True)
            
            if not result:
                return False, "User not found"
            
            user_data = result[0]
            stored_hash = user_data['password_hash']
            salt = user_data['salt']
            
            # Hash the provided passphrase with the stored salt
            provided_hash = self.hash_password(passphrase, salt)
            
            if provided_hash == stored_hash:
                return True, "Passphrase valid"
            else:
                return False, "Invalid passphrase"
                
        except Exception as e:
            return False, f"Passphrase validation failed: {str(e)}"

    def generate_new_keys(self, user_id: int, passphrase: str) -> Tuple[bool, str]:
        """Generate new RSA keys for existing user"""
        try:
            # Verify user exists and validate passphrase
            query = "SELECT email FROM users WHERE id = ?"
            result = self.db.execute_query(query, (user_id,), fetch=True)
            
            if not result:
                return False, "User not found"
            
            email = result[0]['email']
            
            # Validate passphrase before generating keys
            passphrase_valid, passphrase_msg = self.validate_user_passphrase(user_id, passphrase)
            if not passphrase_valid:
                self.logger.log_activity(action="KEY_GENERATION", status="failure", 
                                             details=f"Invalid passphrase for key generation: {email}", email=email)
                return False, "Invalid passphrase"
            
            # Generate new keys
            key_success, key_message, key_data = self.key_manager.create_user_keys(user_id, passphrase)
            
            if key_success:
                self.logger.log_activity(action="KEY_GENERATION", status="success", 
                                             details=f"New RSA keys generated for user: {email}", email=email)
                return True, "New RSA keys generated successfully"
            else:
                return False, key_message
                
        except Exception as e:
            self.logger.log_activity(action="KEY_GENERATION", status="failure", 
                                         details=f"Key generation failed for user ID {user_id}: {str(e)}", email=self.db.get_user_email_by_id(user_id))
            return False, f"Key generation failed: {str(e)}"
    
    def renew_user_keys(self, user_id: int, passphrase: str) -> Tuple[bool, str]:
        """Renew existing RSA keys for user"""
        try:
            # Verify user exists
            query = "SELECT email FROM users WHERE id = ?"
            result = self.db.execute_query(query, (user_id,), fetch=True)
            
            if not result:
                return False, "User not found"
            
            email = result[0]['email']
            
            # Validate passphrase before renewing keys
            passphrase_valid, passphrase_msg = self.validate_user_passphrase(user_id, passphrase)
            if not passphrase_valid:
                self.logger.log_activity(action="KEY_RENEWAL", status="failure", 
                                             details=f"Invalid passphrase for key renewal: {email}", email=email)
                return False, "Invalid passphrase"
            
            # Renew keys using key manager
            renew_success, renew_message, new_key_data = self.key_manager.renew_user_keys(user_id, passphrase)
            
            if renew_success:
                self.logger.log_activity(action="KEY_RENEWAL", status="success", 
                                             details=f"RSA keys renewed for user: {email}", email=email)
                return True, "RSA keys renewed successfully"
            else:
                return False, renew_message
                
        except Exception as e:
            self.logger.log_activity(action="KEY_RENEWAL", status="failure", 
                                         details=f"Key renewal failed for user ID {user_id}: {str(e)}", email=self.db.get_user_email_by_id(user_id))
            return False, f"Key renewal failed: {str(e)}"

    def recover_account_with_code(self, email: str, recovery_code: str, new_password: str) -> Tuple[bool, str]:
        """Recover account using recovery code, expire old keys, and generate new ones."""
        try:
            # Get user information
            query = "SELECT id FROM users WHERE email = ?"
            result = self.db.execute_query(query, (email.lower().strip(),), fetch=True)
            
            if not result:
                self.logger.log_activity(action="ACCOUNT_RECOVERY", status="failure", 
                                             details=f"Account recovery attempted for non-existent email: {email}", email=email)
                return False, "Email not found"
            
            user_id = result[0]['id']

            # Verify recovery code
            if not self.db.verify_recovery_code(user_id, self.hash_recovery_code(recovery_code)):
                 self.logger.log_activity(action="ACCOUNT_RECOVERY", status="failure", 
                                             details=f"Invalid recovery code for user: {email}", email=email)
                 return False, "Invalid recovery code"

            # Validate new password strength
            pwd_valid, pwd_msg = self.validate_password_strength(new_password)
            if not pwd_valid:
                return False, pwd_msg
            
            # Generate new salt and hash for new password
            new_salt = self.generate_salt()
            new_password_hash = self.hash_password(new_password, new_salt)
            
            # Generate a new recovery code
            new_recovery_code = self.generate_recovery_code()
            new_recovery_code_hash = self.hash_recovery_code(new_recovery_code)

            # Expire any existing keys for the user
            self.key_manager.expire_all_user_keys(user_id)
            self.logger.log_activity(action="KEY_EXPIRATION", status="success",
                                     details=f"All keys for user {email} expired during account recovery.",
                                     email=email)
            
            # Generate new RSA keys with the new passphrase
            key_success, key_message, _ = self.key_manager.create_user_keys(user_id, new_password)
            if not key_success:
                return False, f"Failed to generate new keys after recovery: {key_message}"
                
            self.logger.log_activity(action="KEY_GENERATION", status="success",
                                     details=f"New keys generated for user {email} during account recovery.",
                                     email=email)

            # Update user password and set new recovery code
            query = """
                UPDATE users 
                SET password_hash = ?, salt = ?, recovery_code_hash = ? 
                WHERE id = ?
            """
            self.db.execute_query(query, (new_password_hash, new_salt, new_recovery_code_hash, user_id))
            
            self.logger.log_activity(action="ACCOUNT_RECOVERY", status="success", 
                                         details=f"Account recovered and new keys generated for user: {email}", email=email)
            
            return True, f"Account recovered successfully. Your old keys have expired and new keys have been generated. Here is your new recovery code: {new_recovery_code}"
            
        except Exception as e:
            self.logger.log_activity(action="ACCOUNT_RECOVERY", status="failure", 
                                         details=f"Account recovery failed for {email}: {str(e)}", email=email)
            return False, f"Account recovery failed: {str(e)}"
    
    def logout_user(self, user_info: Dict = None):
        """Logout the current user and clear global session"""
        if user_info:
            self.logger.log_activity(
                action="user_logout",
                status="success",
                details=f"User logged out: {user_info['email']}",
                email=user_info['email']
            )
        
        # Clear the global user session
        global_user_session.clear_current_user()

auth_manager = AuthManager() 