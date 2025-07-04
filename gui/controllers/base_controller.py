"""
Base Controller Class
Provides common functionality for all controllers that interface 
between GUI components and business logic modules
"""

from PyQt5.QtCore import QObject, pyqtSignal

from ..app import session_manager
from modules.logger import security_logger

class BaseController(QObject):
    """Base class for all controllers"""
    
    # Common signals
    operation_started = pyqtSignal(str)  # Emitted when operation starts
    operation_completed = pyqtSignal(bool, str, dict)  # success, message, data
    operation_progress = pyqtSignal(int, str)  # progress percentage, status
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.session_manager = session_manager
    
    def get_current_user_id(self):
        """Get current user ID from session"""
        return self.session_manager.get_user_id()
    
    def get_current_user_email(self):
        """Get current user email from session"""
        return self.session_manager.get_user_email()
    
    def get_current_user_role(self):
        """Get current user role from session"""
        return self.session_manager.get_user_role()
    
    def is_admin(self):
        """Check if current user is admin"""
        return self.session_manager.is_admin()
    
    def is_authenticated(self):
        """Check if user is fully authenticated"""
        return self.session_manager.is_fully_authenticated()
    
    def log_action(self, action, status='success', details=None):
        """Log user action"""
        user_id = self.get_current_user_id()
        security_logger.log_activity(
            user_id=user_id,
            action=action,
            status=status,
            details=details
        )
    
    def emit_operation_started(self, operation_name):
        """Emit operation started signal"""
        self.operation_started.emit(operation_name)
        self.log_action(f'{operation_name}_started', 'info')
    
    def emit_operation_completed(self, success, message, data=None):
        """Emit operation completed signal"""
        self.operation_completed.emit(success, message, data or {})
    
    def emit_progress(self, percentage, status):
        """Emit progress update signal"""
        self.operation_progress.emit(percentage, status)
    
    def handle_error(self, operation, error, log_details=None):
        """Handle and log errors consistently"""
        error_msg = str(error)
        self.log_action(
            action=f'{operation}_error',
            status='failure',
            details=log_details or error_msg
        )
        self.emit_operation_completed(False, error_msg)
        return False, error_msg
    
    def validate_authentication(self):
        """Validate that user is authenticated for the operation"""
        if not self.is_authenticated():
            error_msg = "User not authenticated or MFA not completed"
            self.log_action('unauthorized_access_attempt', 'failure', error_msg)
            return False, error_msg
        return True, "Authenticated"
    
    def validate_admin_access(self):
        """Validate that user has admin access"""
        auth_result, auth_msg = self.validate_authentication()
        if not auth_result:
            return auth_result, auth_msg
            
        if not self.is_admin():
            error_msg = "Admin access required"
            self.log_action('unauthorized_admin_attempt', 'failure', error_msg)
            return False, error_msg
        return True, "Admin access granted" 
