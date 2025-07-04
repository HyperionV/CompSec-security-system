"""
Main PyQt5 Application Class
Entry point for the Security Application GUI
"""

import sys
import os
from PyQt5.QtWidgets import QApplication, QMessageBox
from PyQt5.QtCore import QTimer, pyqtSignal, QObject
from PyQt5.QtGui import QFont

# Add modules directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.database import db
from modules.logger import security_logger
from modules.key_lifecycle import lifecycle_service

class SecurityApp(QApplication):
    """Main Security Application class"""
    
    def __init__(self, argv):
        super().__init__(argv)
        self.setApplicationName("Security Application")
        self.setApplicationVersion("1.0.0")
        self.setOrganizationName("Security App Team")
        
        # Initialize application
        self.init_application()
        self.setup_styling()
        
    def init_application(self):
        """Initialize application components"""
        try:
            # Create necessary directories
            os.makedirs("data", exist_ok=True)
            os.makedirs("data/qr_codes", exist_ok=True)
            os.makedirs("data/encrypted", exist_ok=True)
            os.makedirs("data/decrypted", exist_ok=True)
            os.makedirs("data/signatures", exist_ok=True)
            os.makedirs("logs", exist_ok=True)
            
            # Initialize database
            if not db.initialize_database():
                self.show_critical_error("Database initialization failed")
                return False
                
            # Initialize key lifecycle service
            try:
                lifecycle_service.run_daily_lifecycle_check()
            except Exception as e:
                security_logger.log_activity(
                    action='app_init_warning',
                    status='warning',
                    details=f'Key lifecycle warning: {str(e)}'
                )
            
            security_logger.log_activity(
                action='gui_app_start',
                status='success',
                details='GUI application initialized successfully'
            )
            return True
            
        except Exception as e:
            self.show_critical_error(f"Application initialization failed: {str(e)}")
            return False
    
    def setup_styling(self):
        """Setup application-wide styling"""
        # Set default font
        font = QFont("Arial", 9)
        self.setFont(font)
        
        # Apply stylesheet for consistent appearance
        stylesheet = """
        QMainWindow {
            background-color: #f0f0f0;
        }
        
        QDialog {
            background-color: #f0f0f0;
        }
        
        QLabel {
            color: #333333;
        }
        
        QPushButton {
            background-color: #e0e0e0;
            border: 1px solid #cccccc;
            padding: 6px 12px;
            border-radius: 3px;
            min-width: 80px;
        }
        
        QPushButton:hover {
            background-color: #d0d0d0;
        }
        
        QPushButton:pressed {
            background-color: #c0c0c0;
        }
        
        QPushButton:disabled {
            background-color: #f5f5f5;
            color: #999999;
        }
        
        QLineEdit {
            border: 1px solid #cccccc;
            padding: 4px;
            border-radius: 3px;
        }
        
        QLineEdit:focus {
            border: 1px solid #0078d4;
        }
        
        QTextEdit {
            border: 1px solid #cccccc;
            border-radius: 3px;
        }
        
        QComboBox {
            border: 1px solid #cccccc;
            padding: 4px;
            border-radius: 3px;
        }
        
        QGroupBox {
            font-weight: bold;
            border: 1px solid #cccccc;
            margin-top: 5px;
            padding-top: 10px;
            border-radius: 3px;
        }
        
        QGroupBox::title {
            subcontrol-origin: margin;
            left: 10px;
            padding: 0 5px 0 5px;
        }
        
        QTableWidget {
            border: 1px solid #cccccc;
            gridline-color: #dddddd;
        }
        
        QHeaderView::section {
            background-color: #e8e8e8;
            border: 1px solid #cccccc;
            padding: 4px;
        }
        """
        
        self.setStyleSheet(stylesheet)
    
    def show_critical_error(self, message):
        """Show critical error message and exit"""
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Critical)
        msg.setWindowTitle("Critical Error")
        msg.setText("A critical error occurred:")
        msg.setDetailedText(message)
        msg.setStandardButtons(QMessageBox.Ok)
        msg.exec_()
        sys.exit(1)


class SessionManager(QObject):
    """
    Adapted session manager for PyQt5 GUI context
    Manages user authentication state and emits signals for state changes
    """
    
    # Signals for session state changes
    user_logged_in = pyqtSignal(dict)  # Emitted when user logs in
    mfa_completed = pyqtSignal()       # Emitted when MFA is completed
    user_logged_out = pyqtSignal()     # Emitted when user logs out
    session_expired = pyqtSignal()     # Emitted when session expires
    
    def __init__(self):
        super().__init__()
        self.current_user = None
        self.is_authenticated = False
        self.mfa_verified = False
        self._session_timer = QTimer()
        self._session_timer.timeout.connect(self._check_session_timeout)
        self._session_timeout_minutes = 30  # 30 minute session timeout
        
        # Initialize backend module connections
        self.database = db
        self.logger = security_logger
        self.key_manager = None  # Will be initialized after login
    
    def login(self, user_info: dict):
        """Log in user and start session management"""
        self.current_user = user_info
        self.is_authenticated = True
        self.mfa_verified = False
        
        # Initialize key manager for this user
        from modules.key_manager import KeyManager
        self.key_manager = KeyManager(
            user_info.get('email', ''),
            self.database,
            self.logger
        )
        
        # Start session timeout timer
        self._session_timer.start(60000)  # Check every minute
        
        # Log the login
        security_logger.log_activity(
            user_id=user_info.get('id'),
            action='gui_login',
            status='success',
            details=f"User logged in: {user_info.get('email')}"
        )
        
        self.user_logged_in.emit(user_info)
    
    def complete_mfa(self):
        """Complete MFA verification"""
        self.mfa_verified = True
        
        # Log MFA completion
        if self.current_user:
            security_logger.log_activity(
                user_id=self.current_user.get('id'),
                action='gui_mfa_complete',
                status='success',
                details="MFA verification completed"
            )
        
        self.mfa_completed.emit()
    
    def logout(self):
        """Log out user and clear session"""
        if self.current_user:
            security_logger.log_activity(
                user_id=self.current_user.get('id'),
                action='gui_logout',
                status='success',
                details="User logged out"
            )
        
        self.current_user = None
        self.is_authenticated = False
        self.mfa_verified = False
        self.key_manager = None
        
        # Stop session timer
        self._session_timer.stop()
        
        self.user_logged_out.emit()
    
    def is_fully_authenticated(self) -> bool:
        """Check if user is fully authenticated (login + MFA)"""
        return self.is_authenticated and self.mfa_verified
    
    def get_user_id(self) -> int:
        """Get current user ID"""
        return self.current_user.get('id') if self.current_user else None
    
    def get_user_email(self) -> str:
        """Get current user email"""
        return self.current_user.get('email') if self.current_user else None
    
    def get_user_role(self) -> str:
        """Get current user role"""
        return self.current_user.get('role', 'user') if self.current_user else 'user'
    
    def is_admin(self) -> bool:
        """Check if current user is admin"""
        return self.get_user_role() == 'admin'
    
    def _check_session_timeout(self):
        """Check for session timeout (placeholder for future implementation)"""
        # For now, just continue the session
        # In a full implementation, you might check last activity time
        pass


class ApplicationController(QObject):
    """Main application controller that manages the flow between windows"""
    
    def __init__(self, session_manager):
        super().__init__()
        self.session_manager = session_manager
        self.login_window = None
        self.main_dashboard = None
        
    def start_application(self):
        """Start the application with login window"""
        from gui.auth.login_window import LoginWindow
        
        self.login_window = LoginWindow()
        self.login_window.show_main_application.connect(self.show_dashboard)
        self.login_window.authentication_successful.connect(self.handle_authentication)
        self.login_window.show()
        
    def handle_authentication(self, username):
        """Handle successful authentication"""
        # This could be extended to load user data into session manager
        pass
        
    def show_dashboard(self):
        """Show the main dashboard after authentication"""
        from gui.main.main_dashboard import MainDashboard
        
        if self.main_dashboard:
            self.main_dashboard.close()
            
        self.main_dashboard = MainDashboard(self.session_manager)
        self.main_dashboard.logoutRequested.connect(self.handle_logout)
        self.main_dashboard.featureSelected.connect(self.handle_feature_selection)
        self.main_dashboard.show()
        
    def handle_logout(self):
        """Handle logout request from dashboard"""
        if self.main_dashboard:
            self.main_dashboard.close()
            self.main_dashboard = None
            
        self.session_manager.logout()
        self.login_window.show_window()
        
    def handle_feature_selection(self, feature_id):
        """Handle feature selection from dashboard"""
        try:
            if feature_id == 'file_encrypt':
                self.show_file_encryption()
            elif feature_id == 'file_decrypt':
                self.show_file_decryption()
            elif feature_id == 'file_operations':
                self.show_file_operations()
            elif feature_id == 'file_sign':
                self.show_file_signing()
            elif feature_id == 'signature_verify':
                self.show_signature_verification()
            elif feature_id == 'digital_signature':
                self.show_digital_signature_operations()
            elif feature_id == 'key_management':
                self.show_key_management()
            elif feature_id == 'key_generation':
                self.show_key_generation()
            elif feature_id == 'key_status':
                self.show_key_status()
            elif feature_id == 'public_key_search':
                self.show_public_key_search()
            elif feature_id == 'qrgenerate':
                self.show_qr_generation()
            elif feature_id == 'qrscan':
                self.show_qr_scan()
            elif feature_id == 'qr_management':
                self.show_qr_management()
            elif feature_id == 'admin' or feature_id == 'admin_panel':
                self.show_admin_panel()
            elif feature_id == 'user_management':
                self.show_user_management()
            elif feature_id == 'system_statistics':
                self.show_system_statistics()
            elif feature_id == 'security_logs':
                self.show_security_logs()
            else:
                # Placeholder for other features
                print(f"Feature selected: {feature_id}")
                
        except Exception as e:
            from gui.utils.message_boxes import MessageBoxes
            MessageBoxes.showError(
                self.main_dashboard, 
                "Feature Error", 
                f"Failed to open feature '{feature_id}': {e}"
            )
    
    def show_file_encryption(self):
        """Show file encryption interface"""
        from gui.controllers.file_operations_controller import FileOperationsController
        
        if not hasattr(self, 'file_ops_controller'):
            self.file_ops_controller = FileOperationsController(
                self.session_manager, 
                self.main_dashboard
            )
        
        self.file_ops_controller.showEncryptDialog()
    
    def show_file_decryption(self):
        """Show file decryption interface"""
        from gui.controllers.file_operations_controller import FileOperationsController
        
        if not hasattr(self, 'file_ops_controller'):
            self.file_ops_controller = FileOperationsController(
                self.session_manager, 
                self.main_dashboard
            )
        
        self.file_ops_controller.showDecryptDialog()
    
    def show_file_operations(self):
        """Show general file operations interface"""
        from gui.controllers.file_operations_controller import FileOperationsController
        
        if not hasattr(self, 'file_ops_controller'):
            self.file_ops_controller = FileOperationsController(
                self.session_manager, 
                self.main_dashboard
            )
        
        self.file_ops_controller.showFileOperations()

    def show_file_signing(self):
        """Show file signing interface"""
        from gui.controllers.digital_signature_controller import DigitalSignatureController
        
        if not hasattr(self, 'digital_sig_controller'):
            self.digital_sig_controller = DigitalSignatureController(self.session_manager)
        
        self.digital_sig_controller.showFileSign()

    def show_signature_verification(self):
        """Show signature verification interface"""
        from gui.controllers.digital_signature_controller import DigitalSignatureController
        
        if not hasattr(self, 'digital_sig_controller'):
            self.digital_sig_controller = DigitalSignatureController(self.session_manager)
        
        self.digital_sig_controller.showSignatureVerify()

    def show_digital_signature_operations(self):
        """Show general digital signature operations interface"""
        from gui.controllers.digital_signature_controller import DigitalSignatureController
        
        if not hasattr(self, 'digital_sig_controller'):
            self.digital_sig_controller = DigitalSignatureController(self.session_manager)
        
        self.digital_sig_controller.showDigitalSignatureOperations()

    def show_key_management(self):
        """Show key management interface"""
        from gui.controllers.key_management_controller import KeyManagementController
        
        if not hasattr(self, 'key_mgmt_controller'):
            self.key_mgmt_controller = KeyManagementController(self.session_manager)
        
        self.key_mgmt_controller.show_key_management()

    def show_key_generation(self):
        """Show key generation interface"""
        from gui.controllers.key_management_controller import KeyManagementController
        
        if not hasattr(self, 'key_mgmt_controller'):
            self.key_mgmt_controller = KeyManagementController(self.session_manager)
        
        self.key_mgmt_controller.show_key_generation()

    def show_key_status(self):
        """Show key status interface"""
        from gui.controllers.key_management_controller import KeyManagementController
        
        if not hasattr(self, 'key_mgmt_controller'):
            self.key_mgmt_controller = KeyManagementController(self.session_manager)
        
        self.key_mgmt_controller.show_key_status()

    def show_public_key_search(self):
        """Show public key search interface"""
        from gui.controllers.key_management_controller import KeyManagementController
        
        if not hasattr(self, 'key_mgmt_controller'):
            self.key_mgmt_controller = KeyManagementController(self.session_manager)
        
        self.key_mgmt_controller.show_public_key_search()

    def show_qr_management(self):
        """Show QR code management interface"""
        from gui.controllers.qr_code_controller import QRCodeController
        
        if not hasattr(self, 'qr_code_controller'):
            self.qr_code_controller = QRCodeController(self.session_manager)
        
        self.qr_code_controller.show_qr_management()

    def show_qr_generation(self):
        """Show QR code generation interface"""
        from gui.controllers.qr_code_controller import QRCodeController
        
        if not hasattr(self, 'qr_code_controller'):
            self.qr_code_controller = QRCodeController(self.session_manager)
        
        self.qr_code_controller.show_qr_generation()

    def show_qr_scan(self):
        """Show QR code scanning interface"""
        from gui.controllers.qr_code_controller import QRCodeController
        
        if not hasattr(self, 'qr_code_controller'):
            self.qr_code_controller = QRCodeController(self.session_manager)
        
        self.qr_code_controller.show_qr_scan()

    def show_admin_panel(self):
        """Show admin panel dashboard"""
        # Check admin access first
        if not self.session_manager.is_admin():
            from gui.utils.message_boxes import MessageBoxes
            MessageBoxes.show_error(
                self.main_dashboard,
                "Access Denied",
                "You do not have administrator privileges."
            )
            return
        
        from gui.admin.admin_dashboard import AdminDashboardWindow
        
        if hasattr(self, 'admin_dashboard') and self.admin_dashboard:
            self.admin_dashboard.close()
        
        self.admin_dashboard = AdminDashboardWindow()
        self.admin_dashboard.feature_selected.connect(self.handle_feature_selection)
        self.admin_dashboard.logout_requested.connect(self.handle_logout)
        self.admin_dashboard.show()

    def show_user_management(self):
        """Show user management interface"""
        # Check admin access first
        if not self.session_manager.is_admin():
            from gui.utils.message_boxes import MessageBoxes
            MessageBoxes.show_error(
                self.main_dashboard,
                "Access Denied", 
                "You do not have administrator privileges."
            )
            return
        
        from gui.admin.user_management_window import UserManagementWindow
        
        if hasattr(self, 'user_management_window') and self.user_management_window:
            self.user_management_window.close()
        
        self.user_management_window = UserManagementWindow()
        self.user_management_window.show()

    def show_system_statistics(self):
        """Show system statistics interface"""
        # Check admin access first
        if not self.session_manager.is_admin():
            from gui.utils.message_boxes import MessageBoxes
            MessageBoxes.show_error(
                self.main_dashboard,
                "Access Denied",
                "You do not have administrator privileges."
            )
            return
        
        from gui.admin.system_statistics_window import SystemStatisticsWindow
        
        if hasattr(self, 'system_statistics_window') and self.system_statistics_window:
            self.system_statistics_window.close()
        
        self.system_statistics_window = SystemStatisticsWindow()
        self.system_statistics_window.show()

    def show_security_logs(self):
        """Show security logs interface"""
        # Check admin access first
        if not self.session_manager.is_admin():
            from gui.utils.message_boxes import MessageBoxes
            MessageBoxes.show_error(
                self.main_dashboard,
                "Access Denied",
                "You do not have administrator privileges."
            )
            return
        
        from gui.admin.security_logs_window import SecurityLogsWindow
        
        if hasattr(self, 'security_logs_window') and self.security_logs_window:
            self.security_logs_window.close()
        
        self.security_logs_window = SecurityLogsWindow()
        self.security_logs_window.show()




# Global session manager instance
session_manager = SessionManager()


def create_app():
    """Create and configure the Security Application"""
    app = SecurityApp(sys.argv)
    return app


def run_gui():
    """Run the GUI application"""
    app = create_app()
    
    # Create application controller and start
    controller = ApplicationController(session_manager)
    controller.start_application()
    
    return app.exec_() 
