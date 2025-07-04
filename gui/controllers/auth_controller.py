"""
Authentication Controller
Interfaces between authentication GUI components and auth.py business logic
"""

import sys
import os

# Add modules directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from .base_controller import BaseController
from modules.auth import AuthManager
from modules.mfa import MFAManager

class AuthController(BaseController):
    """Controller for authentication operations"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.auth_manager = AuthManager()
        self.mfa_manager = MFAManager()
    
    def register_user(self, email, name, phone, address, birth_date, passphrase):
        """Register a new user"""
        try:
            self.emit_operation_started("User Registration")
            
            # Register user through auth manager
            success, message = self.auth_manager.register_user(
                email=email,
                name=name,
                password=passphrase,
                phone=phone,
                address=address,
                birth_date=birth_date
            )
            
            if success:
                self.log_action('user_registration', 'success', f'New user registered: {email}')
                self.emit_operation_completed(True, message, {'email': email})
            else:
                self.log_action('user_registration', 'failure', f'Registration failed for {email}: {message}')
                self.emit_operation_completed(False, message)
                
            return success, message
            
        except Exception as e:
            return self.handle_error('user_registration', e)
    
    def login_user(self, email, passphrase):
        """Initiate user login process"""
        try:
            self.emit_operation_started("User Login")
            
            # Check account lockout first
            is_locked, lockout_msg, remaining_time = self.auth_manager.check_account_lockout(email)
            if is_locked:
                self.log_action('login_attempt', 'failure', f'Account locked: {email}')
                self.emit_operation_completed(False, lockout_msg, {'lockout_time': remaining_time})
                return False, lockout_msg, {'lockout_time': remaining_time}
            
            # Verify credentials
            success, message, user_info = self.auth_manager.initiate_login_flow(email, passphrase)
            
            if success:
                # Login successful, now need MFA
                self.log_action('login_credentials', 'success', f'Credentials verified: {email}')
                
                # Store user info temporarily for MFA
                self._pending_user_info = user_info
                
                self.emit_operation_completed(True, message, user_info)
                return True, message, user_info
            else:
                self.log_action('login_attempt', 'failure', f'Invalid credentials: {email}')
                self.emit_operation_completed(False, message)
                return False, message, None
                
        except Exception as e:
            return self.handle_error('user_login', e)
    
    def send_mfa_code(self, user_id):
        """Send MFA verification code"""
        try:
            self.emit_operation_started("Send MFA Code")
            
            # Send OTP through MFA manager
            success, message = self.mfa_manager.send_otp(user_id)
            
            if success:
                self.log_action('mfa_code_sent', 'success', f'MFA code sent to user {user_id}')
                self.emit_operation_completed(True, message)
            else:
                self.log_action('mfa_code_sent', 'failure', f'Failed to send MFA code to user {user_id}')
                self.emit_operation_completed(False, message)
                
            return success, message
            
        except Exception as e:
            return self.handle_error('send_mfa_code', e)
    
    def verify_mfa_and_complete_login(self, user_info, mfa_code):
        """Verify MFA code and complete login process"""
        try:
            self.emit_operation_started("MFA Verification")
            
            # Verify MFA code
            success, message = self.auth_manager.complete_login_with_mfa(user_info, mfa_code)
            
            if success:
                # MFA successful - complete login in session manager
                self.session_manager.login(user_info)
                self.session_manager.complete_mfa()
                
                self.log_action('mfa_verification', 'success', f'MFA completed for user {user_info.get("id")}')
                self.emit_operation_completed(True, message, user_info)
                
                # Clear pending user info
                self._pending_user_info = None
                
            else:
                self.log_action('mfa_verification', 'failure', f'Invalid MFA code for user {user_info.get("id")}')
                self.emit_operation_completed(False, message)
                
            return success, message
            
        except Exception as e:
            return self.handle_error('mfa_verification', e)
    
    def recover_account(self, email, recovery_code, new_passphrase):
        """Recover account using recovery code"""
        try:
            self.emit_operation_started("Account Recovery")
            
            # Recover account through auth manager
            success, message = self.auth_manager.recover_account_with_code(email, recovery_code, new_passphrase)
            
            if success:
                self.log_action('account_recovery', 'success', f'Account recovered: {email}')
                self.emit_operation_completed(True, message)
            else:
                self.log_action('account_recovery', 'failure', f'Account recovery failed: {email}')
                self.emit_operation_completed(False, message)
                
            return success, message
            
        except Exception as e:
            return self.handle_error('account_recovery', e)
    
    def validate_email_format(self, email):
        """Validate email format"""
        return self.auth_manager.validate_email(email)
    
    def validate_password_strength(self, password):
        """Validate password strength"""
        return self.auth_manager.validate_password_strength(password)
    
    def logout_user(self):
        """Logout current user"""
        try:
            user_email = self.session_manager.get_user_email()
            self.session_manager.logout()
            
            self.log_action('user_logout', 'success', f'User logged out: {user_email}')
            return True, "Logged out successfully"
            
        except Exception as e:
            return self.handle_error('user_logout', e) 
