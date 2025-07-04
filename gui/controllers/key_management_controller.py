from PyQt5.QtWidgets import QMessageBox
from .base_controller import BaseController
from ..key_mgmt import KeyManagementWindow, KeyGenerationDialog, PublicKeySearchDialog
from ..utils import MessageBoxes

class KeyManagementController(BaseController):
    def __init__(self, session_manager):
        super().__init__(session_manager)
        self.key_management_window = None
    
    def show_key_management(self):
        """Show the main key management window"""
        try:
            if not self.validate_session():
                return
            
            # Initialize public key manager if needed
            self.ensure_public_key_manager()
            
            self.key_management_window = KeyManagementWindow(
                self.session_manager,
                parent=None
            )
            
            self.key_management_window.show()
            self.key_management_window.raise_()
            self.key_management_window.activateWindow()
            
        except Exception as e:
            MessageBoxes.show_error(
                None,
                "Key Management Error",
                f"Failed to open key management window: {str(e)}"
            )
    
    def show_key_generation(self):
        """Show key generation dialog"""
        try:
            if not self.validate_session():
                return
            
            if not self.session_manager.key_manager:
                MessageBoxes.warning(None, "Key Manager", "Key manager not available.")
                return
            
            dialog = KeyGenerationDialog(
                self.session_manager.key_manager,
                self.session_manager.current_user['id'],
                parent=None
            )
            
            result = dialog.exec_()
            
            if result == dialog.Accepted:
                MessageBoxes.information(
                    None,
                    "Key Generation",
                    "RSA key pair generated successfully!"
                )
                
        except Exception as e:
            MessageBoxes.show_error(
                None,
                "Key Generation Error",
                f"Failed to generate keys: {str(e)}"
            )
    
    def show_public_key_search(self):
        """Show public key search dialog"""
        try:
            if not self.validate_session():
                return
            
            # Ensure public key manager exists
            self.ensure_public_key_manager()
            
            dialog = PublicKeySearchDialog(
                self.session_manager.public_key_manager,
                parent=None
            )
            
            dialog.exec_()
            
        except Exception as e:
            MessageBoxes.show_error(
                None,
                "Public Key Search Error",
                f"Failed to open public key search: {str(e)}"
            )
    
    def show_key_status(self):
        """Show key status information"""
        try:
            if not self.validate_session():
                return
            
            if not self.session_manager.key_manager:
                MessageBoxes.warning(None, "Key Manager", "Key manager not available.")
                return
            
            # Check user's key status
            success, message, key_data = self.session_manager.key_manager.check_key_status(
                self.session_manager.current_user['id']
            )
            
            if success and key_data:
                status = key_data.get('status', 'unknown')
                days_remaining = key_data.get('days_remaining', 0)
                created_at = key_data.get('created_at', 'Unknown')
                expires_at = key_data.get('expires_at', 'Unknown')
                
                status_message = f"""
Key Status Information:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Status: {status.replace('_', ' ').title()}
Created: {created_at}
Expires: {expires_at}
Days Remaining: {days_remaining}

Key ID: {key_data.get('key_id', 'Unknown')}
Algorithm: RSA-2048 with AES-256-GCM encryption
                """.strip()
                
                if status == 'expired':
                    MessageBoxes.warning(None, "Key Status - Expired", status_message)
                elif status == 'expiring_soon':
                    MessageBoxes.warning(None, "Key Status - Expiring Soon", status_message)
                else:
                    MessageBoxes.information(None, "Key Status - Valid", status_message)
            else:
                MessageBoxes.information(
                    None,
                    "Key Status",
                    f"No RSA keys found for your account.\n\nMessage: {message}"
                )
                
        except Exception as e:
            MessageBoxes.show_error(
                None,
                "Key Status Error",
                f"Failed to check key status: {str(e)}"
            )
    
    def ensure_public_key_manager(self):
        """Ensure public key manager is initialized"""
        if not hasattr(self.session_manager, 'public_key_manager'):
            from modules.public_key_manager import PublicKeyManager
            self.session_manager.public_key_manager = PublicKeyManager(
                self.session_manager.current_user['email'],
                self.session_manager.database,
                self.session_manager.logger
            )
    
    def validate_key_generation_input(self, passphrase, confirm_passphrase):
        """Validate key generation input"""
        if not passphrase or len(passphrase) < 8:
            return False, "Passphrase must be at least 8 characters long."
        
        if passphrase != confirm_passphrase:
            return False, "Passphrases do not match."
        
        if passphrase.strip() != passphrase:
            return False, "Passphrase cannot start or end with whitespace."
        
        return True, "Valid input"
    
    def validate_email_for_search(self, email):
        """Validate email format for public key search"""
        if not email or not email.strip():
            return False, "Email address is required."
        
        email = email.strip()
        
        if '@' not in email or '.' not in email:
            return False, "Please enter a valid email address."
        
        if len(email) < 5:
            return False, "Email address is too short."
        
        return True, "Valid email" 
