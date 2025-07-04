"""
Account Controller
Interfaces between account management GUI components and auth.py business logic
"""

import sys
import os

# Add modules directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from .base_controller import BaseController
from modules.auth import AuthManager

class AccountController(BaseController):
    """Controller for account management operations"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.auth_manager = AuthManager()
    
    def update_user_profile(self, name=None, phone=None, address=None, birth_date=None):
        """Update user profile information"""
        try:
            # Validate authentication
            auth_result, auth_msg = self.validate_authentication()
            if not auth_result:
                return auth_result, auth_msg
                
            user_id = self.get_current_user_id()
            if not user_id:
                return False, "User ID not found in session"
            
            self.emit_operation_started("Profile Update")
            
            # Call auth manager to update profile
            success, message = self.auth_manager.update_user_profile(
                user_id=user_id,
                name=name,
                phone=phone,
                address=address,
                birth_date=birth_date
            )
            
            if success:
                self.log_action('profile_update', 'success', f'Profile updated for user {user_id}')
                self.emit_operation_completed(True, message, {
                    'user_id': user_id,
                    'name': name,
                    'phone': phone,
                    'address': address,
                    'birth_date': birth_date
                })
            else:
                self.log_action('profile_update', 'failure', f'Profile update failed for user {user_id}: {message}')
                self.emit_operation_completed(False, message)
                
            return success, message
            
        except Exception as e:
            return self.handle_error('profile_update', e)
    
    def change_user_passphrase(self, current_password, new_password):
        """Change user passphrase with key re-encryption"""
        try:
            # Validate authentication
            auth_result, auth_msg = self.validate_authentication()
            if not auth_result:
                return auth_result, auth_msg
                
            user_id = self.get_current_user_id()
            if not user_id:
                return False, "User ID not found in session"
            
            self.emit_operation_started("Passphrase Change")
            
            # Call auth manager to change passphrase
            success, message = self.auth_manager.change_passphrase(
                user_id=user_id,
                current_password=current_password,
                new_password=new_password
            )
            
            if success:
                self.log_action('passphrase_change', 'success', f'Passphrase changed for user {user_id}')
                self.emit_operation_completed(True, message, {'user_id': user_id})
            else:
                self.log_action('passphrase_change', 'failure', f'Passphrase change failed for user {user_id}: {message}')
                self.emit_operation_completed(False, message)
                
            return success, message
            
        except Exception as e:
            return self.handle_error('passphrase_change', e)
    
    def generate_new_keys(self, passphrase):
        """Generate new RSA keys for current user"""
        try:
            # Validate authentication
            auth_result, auth_msg = self.validate_authentication()
            if not auth_result:
                return auth_result, auth_msg
                
            user_id = self.get_current_user_id()
            if not user_id:
                return False, "User ID not found in session"
            
            self.emit_operation_started("Key Generation")
            
            # Call auth manager to generate new keys
            success, message = self.auth_manager.generate_new_keys(
                user_id=user_id,
                passphrase=passphrase
            )
            
            if success:
                self.log_action('key_generation', 'success', f'New keys generated for user {user_id}')
                self.emit_operation_completed(True, message, {'user_id': user_id})
            else:
                self.log_action('key_generation', 'failure', f'Key generation failed for user {user_id}: {message}')
                self.emit_operation_completed(False, message)
                
            return success, message
            
        except Exception as e:
            return self.handle_error('key_generation', e)
    
    def renew_user_keys(self, passphrase):
        """Renew existing RSA keys for current user"""
        try:
            # Validate authentication
            auth_result, auth_msg = self.validate_authentication()
            if not auth_result:
                return auth_result, auth_msg
                
            user_id = self.get_current_user_id()
            if not user_id:
                return False, "User ID not found in session"
            
            self.emit_operation_started("Key Renewal")
            
            # Call auth manager to renew keys
            success, message = self.auth_manager.renew_user_keys(
                user_id=user_id,
                passphrase=passphrase
            )
            
            if success:
                self.log_action('key_renewal', 'success', f'Keys renewed for user {user_id}')
                self.emit_operation_completed(True, message, {'user_id': user_id})
            else:
                self.log_action('key_renewal', 'failure', f'Key renewal failed for user {user_id}: {message}')
                self.emit_operation_completed(False, message)
                
            return success, message
            
        except Exception as e:
            return self.handle_error('key_renewal', e)
    
    def validate_password_strength(self, password):
        """Validate password strength"""
        return self.auth_manager.validate_password_strength(password)
    
    def get_current_user_info(self):
        """Get current user information from session"""
        try:
            if not self.is_authenticated():
                return None, "User not authenticated"
                
            user_info = {
                'id': self.get_current_user_id(),
                'email': self.get_current_user_email(),
                'role': self.get_current_user_role(),
                'is_admin': self.is_admin()
            }
            
            # Get additional user details from session if available
            if hasattr(self.session_manager, 'current_user') and self.session_manager.current_user:
                current_user = self.session_manager.current_user
                user_info.update({
                    'name': current_user.get('name', ''),
                    'phone': current_user.get('phone', ''),
                    'address': current_user.get('address', ''),
                    'birth_date': current_user.get('birth_date', '')
                })
            
            return user_info, "User info retrieved"
            
        except Exception as e:
            return None, f"Error retrieving user info: {str(e)}"
