import sys
import os
from PyQt5.QtWidgets import QApplication
from PyQt5.QtCore import Qt

# Add project root to Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.database import DatabaseManager
from modules.logger import SecurityLogger
from modules.auth import AuthManager
from modules.mfa import MFAManager
from modules.key_manager import KeyManager
from modules.key_lifecycle import lifecycle_service
from modules.qr_handler import qr_handler
from modules.file_crypto import FileCrypto
from modules.digital_signature import DigitalSignature
from modules.signature_verification import SignatureVerification
from modules.public_key_manager import PublicKeyManager

from .main_window import MainWindow
from .login_screen import LoginScreen
from .mfa_screen import MFAScreen
from .main_app_screen import MainAppScreen

class UserSession:
    """Manage user session state"""
    def __init__(self):
        self.user_info = None
        self.is_authenticated = False
        self.mfa_completed = False
    
    def login(self, user_info):
        self.user_info = user_info
        self.is_authenticated = True
    
    def complete_mfa(self):
        self.mfa_completed = True
    
    def logout(self):
        self.user_info = None
        self.is_authenticated = False
        self.mfa_completed = False
    
    def is_fully_authenticated(self):
        return self.is_authenticated and self.mfa_completed

class SecurityAppGUI:
    def __init__(self):
        self.app = None
        self.main_window = None
        self.user_session = UserSession()
        self.managers = {}
        self.screens = {}
        
        # Initialize application components
        self.initialize_components()
    
    def initialize_components(self):
        """Initialize all application components"""
        print("Initializing Security Application GUI...")
        
        # Create necessary directories
        os.makedirs("data", exist_ok=True)
        os.makedirs("data/qr_codes", exist_ok=True)
        os.makedirs("data/encrypted", exist_ok=True)
        os.makedirs("data/decrypted", exist_ok=True)
        os.makedirs("data/signatures", exist_ok=True)
        
        # Initialize database
        print("- Setting up database...")
        db = DatabaseManager()
        if not db.initialize_database():
            print("  ✗ Database initialization failed")
            sys.exit(1)
        print("  ✓ Database initialized successfully")
        
        # Initialize managers
        print("- Initializing security managers...")
        self.managers = {
            'db': db,
            'logger': SecurityLogger(),
            'auth_manager': AuthManager(),
            'mfa_manager': MFAManager(),
            'key_manager': KeyManager(),
            'qr_handler': qr_handler,
            'file_crypto': FileCrypto()
            # Note: digital_signature, signature_verification, and public_key_manager
            # will be created after login when user_email becomes available
        }
        
        # Initialize key lifecycle service
        print("- Initializing key lifecycle management...")
        try:
            lifecycle_service.run_daily_lifecycle_check()
            print("  ✓ Key lifecycle management initialized")
        except Exception as e:
            print(f"  ⚠ Key lifecycle warning: {str(e)}")
        
        print("✓ Application components initialized successfully")
    
    def run(self):
        """Run the GUI application"""
        # Create QApplication
        self.app = QApplication(sys.argv)
        self.app.setApplicationName("Security Application")
        self.app.setApplicationVersion("1.0")
        
        # Create main window
        self.main_window = MainWindow()
        
        # Create and setup screens
        self.setup_screens()
        
        # Start with login screen
        self.main_window.show_login_screen()
        self.main_window.show()
        
        # Log application start
        self.managers['logger'].log_activity(
            action='app_start_gui', 
            status='success', 
            details='GUI application started',
            email=None
        )
        
        # Run application event loop
        try:
            sys.exit(self.app.exec_())
        except Exception as e:
            self.managers['logger'].log_activity(
                action='app_error', 
                status='failure', 
                details=f'Application error: {str(e)}',
                email=None
            )
            raise
    
    def setup_screens(self):
        """Setup all application screens"""
        # Login screen
        self.screens['login'] = LoginScreen(self.managers['auth_manager'], self.main_window)
        self.screens['login'].login_successful.connect(self.handle_login_success)
        self.main_window.add_login_screen(self.screens['login'])
        
        # MFA screen (will be created when needed)
        self.screens['mfa'] = None
        
        # Main app screen (will be created after MFA)
        self.screens['main_app'] = None
    
    def reset_all_screens(self):
        """Reset all screens to their initial state"""
        # Reset login screen
        if self.screens['login'] and hasattr(self.screens['login'], 'reset_for_new_session'):
            self.screens['login'].reset_for_new_session()
        
        # Clean up and reset other screens
        self.main_window.cleanup_screens()
        self.screens['mfa'] = None
        self.screens['main_app'] = None
        
        # Clear user-dependent managers
        if 'digital_signature' in self.managers:
            del self.managers['digital_signature']
        if 'signature_verification' in self.managers:
            del self.managers['signature_verification']
        if 'public_key_manager' in self.managers:
            del self.managers['public_key_manager']

    def handle_login_success(self, user_info):
        """Handle successful login - show MFA screen"""
        # Clear any existing global and local session first
        from modules.auth import global_user_session
        global_user_session.clear_current_user()
        self.user_session.logout()
        
        # Set new user session
        self.user_session.login(user_info)
        
        # Always create a fresh MFA screen for new login to avoid state issues
        if self.screens['mfa']:
            # Cleanup old MFA screen properly
            if hasattr(self.screens['mfa'], 'cleanup'):
                self.screens['mfa'].cleanup()
            # Disconnect old signals
            try:
                self.screens['mfa'].mfa_successful.disconnect()
                self.screens['mfa'].back_to_login.disconnect()
            except:
                pass  # Ignore if signals already disconnected
        
        # Create new MFA screen for this user
        self.screens['mfa'] = MFAScreen(
            self.managers['auth_manager'],
            self.managers['mfa_manager'], 
            user_info,
            self.main_window
        )
        self.screens['mfa'].mfa_successful.connect(self.handle_mfa_success)
        self.screens['mfa'].back_to_login.connect(self.handle_back_to_login)
        self.main_window.add_mfa_screen(self.screens['mfa'])
        
        self.main_window.show_mfa_screen()
    
    def handle_mfa_success(self):
        """Handle successful MFA - show main application"""
        self.user_session.complete_mfa()
        
        # Create user-dependent objects now that user_email is available
        user_email = self.user_session.user_info['email']
        
        # Create DigitalSignature and SignatureVerification with user context
        from modules.digital_signature import DigitalSignature
        from modules.signature_verification import SignatureVerification
        
        self.managers['digital_signature'] = DigitalSignature(
            user_email, 
            self.managers['key_manager'], 
            self.managers['db'], 
            self.managers['logger']
        )
        
        self.managers['signature_verification'] = SignatureVerification(
            user_email,
            self.managers['db'],
            self.managers['logger']
        )
        
        from modules.public_key_manager import PublicKeyManager
        
        self.managers['public_key_manager'] = PublicKeyManager(
            user_email,
            self.managers['db'],
            self.managers['logger']
        )
        
        # Always create a fresh main app screen for new user to avoid state issues
        if self.screens['main_app']:
            # Disconnect old signals
            try:
                self.screens['main_app'].logout_requested.disconnect()
            except:
                pass  # Ignore if signals already disconnected
        
        # Create new main app screen for this user
        self.screens['main_app'] = MainAppScreen(
            self.user_session, 
            self.managers,
            self.main_window
        )
        self.screens['main_app'].logout_requested.connect(self.handle_logout)
        self.main_window.add_main_app_screen(self.screens['main_app'])
        
        self.main_window.show_main_app_screen()
    
    def handle_back_to_login(self):
        """Handle back to login from MFA screen"""
        # Clear global session and local session
        from modules.auth import global_user_session
        global_user_session.clear_current_user()
        
        # Use AuthManager's logout method to clear global session
        self.managers['auth_manager'].logout_user(self.user_session.user_info)
        self.user_session.logout()
        
        # Reset all screens systematically
        self.reset_all_screens()
        
        self.main_window.show_login_screen()
    
    def handle_logout(self):
        """Handle logout request"""
        # Clear global session first
        from modules.auth import global_user_session
        global_user_session.clear_current_user()
        
        # Use AuthManager's logout method to clear global session
        self.managers['auth_manager'].logout_user(self.user_session.user_info)
        
        # Clear local session and return to login
        self.user_session.logout()
        
        # Reset all screens systematically
        self.reset_all_screens()
        
        self.main_window.show_login_screen()
    
    def closeEvent(self, event):
        """Handle application close"""
        if self.user_session.is_authenticated:
            self.managers['logger'].log_activity(
                user_id=self.user_session.user_info['id'] if self.user_session.user_info else None,
                action='app_close',
                status='success',
                details='Application closed by user',
                email=self.user_session.user_info['email'] if self.user_session.user_info else None
            )
        
        event.accept()

def main():
    """Main entry point for GUI application"""
    try:
        app = SecurityAppGUI()
        app.run()
    except KeyboardInterrupt:
        print("\nApplication interrupted by user")
    except Exception as e:
        print(f"Application error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main() 