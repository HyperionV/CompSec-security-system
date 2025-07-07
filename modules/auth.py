import hashlib
import secrets
import re
import time
from datetime import datetime, timedelta
from typing import Dict, Tuple, Optional, Union
from .database import DatabaseManager
from .logger import SecurityLogger
from .key_manager import KeyManager

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
                                             details=f"Validation failed: {', '.join(email_msg) if isinstance(email_msg, list) else email_msg}")
                return False, email_msg[0] if isinstance(email_msg, list) else email_msg
            
            pwd_valid, pwd_msg = self.validate_password_strength(password)
            if not pwd_valid:
                self.logger.log_activity(action="USER_REGISTRATION", status="failure", 
                                             details=f"Validation failed: {pwd_msg}")
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
                                                 details=f"Key generation failed, rolled back user: {email}")
                    return False, f"Registration failed: {key_message}"
                
                self.logger.log_activity(action="KEY_MANAGEMENT", status="success", 
                                             details=f"RSA keys generated for new user: {email}")
            
            self.logger.log_registration(email, success=True, 
                                        details=f"New user registered successfully with {'keys' if generate_keys else 'no keys'}")
            
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
                    
            self.logger.log_registration(email, success=False, 
                                       details=f"Registration failed: {str(e)}")
            return False, f"Registration failed: {str(e)}"
    
    def check_account_lockout(self, email: str) -> Tuple[bool, str, int]:
        """Check if account is locked and return status with remaining time"""
        query = "SELECT failed_attempts, locked_until FROM users WHERE email = ?"
        result = self.db.execute_query(query, (email,), fetch=True)
        
        if not result:
            return False, "Account not found", 0
        
        failed_attempts, locked_until = result[0]['failed_attempts'], result[0]['locked_until']
        
        if locked_until and datetime.now() < locked_until:
            remaining_seconds = int((locked_until - datetime.now()).total_seconds())
            remaining_minutes = remaining_seconds // 60
            remaining_seconds = remaining_seconds % 60
            return True, f"Account locked. Try again in {remaining_minutes}m {remaining_seconds}s", remaining_seconds
        
        # Unlock account if lockout period has passed
        if locked_until and datetime.now() >= locked_until:
            self.db.execute_query(
                "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE email = ?",
                (email,)
            )
        
        return False, "Account not locked", 0

    def apply_progressive_delay(self, failed_attempts: int):
        """Apply progressive delay based on failed attempts"""
        if failed_attempts > 0:
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
                                           details=f"Account locked for 5 minutes: {email}")
                else:
                    query = "UPDATE users SET failed_attempts = ? WHERE email = ?"
                    self.db.execute_query(query, (current_attempts, email))

    def verify_login_credentials(self, email: str, password: str) -> Tuple[bool, str, Optional[Dict]]:
        """Verify login credentials with comprehensive security checks"""
        
        # Check if account is locked
        is_locked, lock_message, remaining_time = self.check_account_lockout(email)
        if is_locked:
            self.logger.log_activity(action="LOGIN_ATTEMPT", status="blocked", 
                                         details=f"Locked account login attempt: {email}")
            return False, lock_message, None
        
        # Get user data and failed attempts for progressive delay
        query = """
            SELECT id, email, name, password_hash, salt, role, failed_attempts 
            FROM users WHERE email = ?
        """
        result = self.db.execute_query(query, (email,), fetch=True)
        
        if not result:
            # Apply delay even for non-existent users to prevent email enumeration
            self.apply_progressive_delay(1)
            self.logger.log_activity(action="LOGIN_ATTEMPT", status="failed", 
                                         details=f"Login attempt with non-existent email: {email}")
            return False, "Invalid credentials", None
        
        user_data = result[0]
        user_id = user_data['id']
        user_email = user_data['email'] 
        name = user_data['name']
        stored_hash = user_data['password_hash']
        salt = user_data['salt']
        role = user_data['role']
        failed_attempts = user_data['failed_attempts']
        
        # Apply progressive delay based on previous failed attempts
        self.apply_progressive_delay(failed_attempts)
        
        # Verify password
        provided_hash = self.hash_password(password, salt)
        password_valid = provided_hash == stored_hash
        
        # Update failed attempts
        self.update_failed_attempts(email, password_valid)
        
        if password_valid:
            self.logger.log_activity(action="LOGIN_ATTEMPT", status="success", 
                                         details=f"Successful login: {email}")
            
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
            
            return True, "Login successful", user_info
        else:
            self.logger.log_activity(action="LOGIN_ATTEMPT", status="failed", 
                                         details=f"Invalid password for user: {email}")
            return False, "Invalid credentials", None

    def initiate_login_flow(self, email: str, password: str) -> Tuple[bool, str, Optional[Dict]]:
        """Complete login flow with MFA integration"""
        
        # Step 1: Verify credentials
        credential_valid, message, user_info = self.verify_login_credentials(email, password)
        
        if not credential_valid:
            return False, message, None
        
        # Step 2: Credentials are valid, but user needs MFA
        self.logger.log_activity(action="LOGIN_FLOW", status="info", 
                                     details=f"Credentials verified for {email}, MFA required")
        
        return True, "Credentials verified. Please complete MFA verification.", user_info

    def complete_login_with_mfa(self, user_info: Dict, mfa_token: str, 
                               mfa_type: str = "otp", skip_mfa_verification: bool = False) -> Tuple[bool, str]:
        """Complete login after MFA verification"""
        from .mfa import MFAManager
        
        # Skip MFA verification if already done (e.g., by MFA screen)
        if skip_mfa_verification:
            self.logger.log_activity(action="LOGIN_COMPLETE", status="success", 
                                         details=f"Login completed with MFA: {user_info['email']}")
            return True, f"Login successful! Welcome {user_info['name']}"
        
        mfa_manager = MFAManager()
        
        if mfa_type == "otp":
            # Verify OTP token
            valid, mfa_message = mfa_manager.verify_otp(user_info['id'], mfa_token)
        elif mfa_type == "totp":
            # Verify TOTP token  
            valid, mfa_message = mfa_manager.verify_totp_token(user_info['email'], mfa_token)
        else:
            return False, "Invalid MFA type"
        
        if valid:
            self.logger.log_activity(action="LOGIN_COMPLETE", status="success", 
                                         details=f"Login completed with MFA: {user_info['email']}")
            return True, f"Login successful! Welcome {user_info['name']}"
        else:
            self.logger.log_activity(action="LOGIN_COMPLETE", status="failed", 
                                         details=f"MFA verification failed: {user_info['email']}")
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
                                         details=f"Profile updated for user ID: {user_id}")
            
            return True, "Profile updated successfully"
            
        except Exception as e:
            self.logger.log_activity(action="PROFILE_UPDATE", status="error", 
                                         details=f"Profile update failed for user ID {user_id}: {str(e)}")
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
                self.logger.log_activity(action="PASSPHRASE_CHANGE", status="failed", 
                                             details=f"Invalid current password for user: {email}")
                return False, "Current password is incorrect"
            
            # Validate new password strength
            pwd_valid, pwd_msg = self.validate_password_strength(new_password)
            if not pwd_valid:
                return False, pwd_msg
            
            # Generate new salt and hash
            new_salt = self.generate_salt()
            new_password_hash = self.hash_password(new_password, new_salt)
            
            # Check if user has keys that need re-encryption
            key_success, key_msg, user_keys = self.db.get_user_keys_by_id(user_id)
            
            if key_success and user_keys:
                # Re-encrypt private keys with new passphrase
                for key_record in user_keys:
                    if key_record['status'] == 'valid':
                        # Decrypt with old passphrase and re-encrypt with new
                        old_encrypted_key = key_record['encrypted_private_key'].encode()
                        decrypt_success, decrypt_msg, private_key = self.key_manager.decrypt_private_key(
                            old_encrypted_key, current_password
                        )
                        
                        if not decrypt_success:
                            return False, f"Failed to decrypt existing keys: {decrypt_msg}"
                        
                        # Re-encrypt with new passphrase
                        new_encrypted_key = self.key_manager.encrypt_private_key(private_key, new_password)
                        
                        # Update key in database
                        update_key_query = "UPDATE user_keys SET encrypted_private_key = ? WHERE id = ?"
                        self.db.execute_query(update_key_query, (new_encrypted_key.decode(), key_record['id']))
            
            # Update user password
            query = "UPDATE users SET password_hash = ?, salt = ? WHERE id = ?"
            self.db.execute_query(query, (new_password_hash, new_salt, user_id))
            
            self.logger.log_activity(action="PASSPHRASE_CHANGE", status="success", 
                                         details=f"Passphrase changed for user: {email}")
            
            return True, "Passphrase changed successfully. All RSA keys have been re-encrypted."
            
        except Exception as e:
            self.logger.log_activity(action="PASSPHRASE_CHANGE", status="error", 
                                         details=f"Passphrase change failed for user ID {user_id}: {str(e)}")
            return False, f"Passphrase change failed: {str(e)}"
    
    def generate_new_keys(self, user_id: int, passphrase: str) -> Tuple[bool, str]:
        """Generate new RSA keys for existing user"""
        try:
            # Verify user exists
            query = "SELECT email FROM users WHERE id = ?"
            result = self.db.execute_query(query, (user_id,), fetch=True)
            
            if not result:
                return False, "User not found"
            
            email = result[0]['email']
            
            # Generate new keys
            key_success, key_message, key_data = self.key_manager.create_user_keys(user_id, passphrase)
            
            if key_success:
                self.logger.log_activity(action="KEY_GENERATION", status="success", 
                                             details=f"New RSA keys generated for user: {email}")
                return True, "New RSA keys generated successfully"
            else:
                return False, key_message
                
        except Exception as e:
            self.logger.log_activity(action="KEY_GENERATION", status="error", 
                                         details=f"Key generation failed for user ID {user_id}: {str(e)}")
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
            
            # Renew keys using key manager
            renew_success, renew_message, new_key_data = self.key_manager.renew_user_keys(user_id, passphrase)
            
            if renew_success:
                self.logger.log_activity(action="KEY_RENEWAL", status="success", 
                                             details=f"RSA keys renewed for user: {email}")
                return True, "RSA keys renewed successfully"
            else:
                return False, renew_message
                
        except Exception as e:
            self.logger.log_activity(action="KEY_RENEWAL", status="error", 
                                         details=f"Key renewal failed for user ID {user_id}: {str(e)}")
            return False, f"Key renewal failed: {str(e)}"

    def recover_account_with_code(self, email: str, recovery_code: str, new_password: str) -> Tuple[bool, str]:
        """Recover account using recovery code"""
        try:
            # Get user information
            query = "SELECT id, email, recovery_code_hash FROM users WHERE email = ?"
            result = self.db.execute_query(query, (email.lower().strip(),), fetch=True)
            
            if not result:
                self.logger.log_activity(action="ACCOUNT_RECOVERY", status="failed", 
                                             details=f"Account recovery attempted for non-existent email: {email}")
                return False, "Email not found"
            
            user_data = result[0]
            user_id = user_data['id']
            user_email = user_data['email']
            stored_recovery_hash = user_data['recovery_code_hash']
            
            if not stored_recovery_hash:
                self.logger.log_activity(action="ACCOUNT_RECOVERY", status="failed", 
                                             details=f"No recovery code set for user: {email}")
                return False, "No recovery code available for this account"
            
            # Verify recovery code
            provided_recovery_hash = self.hash_recovery_code(recovery_code.strip().upper())
            
            if provided_recovery_hash != stored_recovery_hash:
                self.logger.log_activity(action="ACCOUNT_RECOVERY", status="failed", 
                                             details=f"Invalid recovery code for user: {email}")
                return False, "Invalid recovery code"
            
            # Validate new password strength
            pwd_valid, pwd_msg = self.validate_password_strength(new_password)
            if not pwd_valid:
                return False, pwd_msg
            
            # Generate new salt and hash for new password
            new_salt = self.generate_salt()
            new_password_hash = self.hash_password(new_password, new_salt)
            
            # Check if user has keys that need re-encryption
            key_success, key_msg, user_keys = self.db.get_user_keys_by_id(user_id)
            
            # Note: For recovery, we can't decrypt existing keys since we don't have the old passphrase
            # The user will need to generate new keys after recovery
            if key_success and user_keys:
                # Mark existing keys as expired since we can't decrypt them
                for key_record in user_keys:
                    if key_record['status'] == 'valid':
                        expire_query = "UPDATE user_keys SET status = 'expired' WHERE id = ?"
                        self.db.execute_query(expire_query, (key_record['id'],))
            
            # Update user password and invalidate recovery code
            query = """
                UPDATE users 
                SET password_hash = ?, salt = ?, recovery_code_hash = NULL 
                WHERE id = ?
            """
            self.db.execute_query(query, (new_password_hash, new_salt, user_id))
            
            self.logger.log_activity(action="ACCOUNT_RECOVERY", status="success", 
                                         details=f"Account recovered for user: {email}")
            
            return True, "Account recovered successfully. Please generate new RSA keys as your old keys have been invalidated for security."
            
        except Exception as e:
            self.logger.log_activity(action="ACCOUNT_RECOVERY", status="error", 
                                         details=f"Account recovery failed for {email}: {str(e)}")
            return False, f"Account recovery failed: {str(e)}"

auth_manager = AuthManager() 