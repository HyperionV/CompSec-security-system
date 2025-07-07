from modules.auth import AuthManager
from modules.mfa import MFAManager


class AuthController:
    def __init__(self):
        self.auth_manager = AuthManager()
        self.mfa_manager = MFAManager()
    
    def check_username_availability(self, email):
        """Check if email is available for registration"""
        email_valid, message = self.auth_manager.validate_email(email)
        return email_valid  # Returns True if available
    
    def register_user(self, username, email, passphrase):
        """Register a new user"""
        try:
            # Use email as name if username provided, or use actual name parameter
            success, message = self.auth_manager.register_user(
                email=email, 
                name=username,  # Use username as name
                password=passphrase
            )
            return {'success': success, 'message': message}
        except Exception as e:
            return {'success': False, 'message': str(e)}