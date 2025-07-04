"""
Base Window Class
Provides common functionality for all main application windows
"""

from PyQt5.QtWidgets import QMainWindow, QWidget, QVBoxLayout, QStatusBar, QDesktopWidget
from PyQt5.QtCore import pyqtSignal
from PyQt5.QtGui import QIcon

from ..app import session_manager
from modules.logger import security_logger

class BaseWindow(QMainWindow):
    """Base class for all main application windows"""
    
    # Signals for window events
    window_closed = pyqtSignal()
    
    def __init__(self, title="Security Application", parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumSize(800, 600)
        
        # Setup window
        self.setup_ui()
        self.connect_session_signals()
        
    def setup_ui(self):
        """Setup the basic UI structure"""
        # Create central widget
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        
        # Create main layout
        self.main_layout = QVBoxLayout(self.central_widget)
        self.main_layout.setContentsMargins(10, 10, 10, 10)
        self.main_layout.setSpacing(10)
        
        # Create status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")
        
    def center_window(self):
        """Centers the window on the screen"""
        qr = self.frameGeometry()
        cp = QDesktopWidget().availableGeometry().center()
        qr.moveCenter(cp)
        self.move(qr.topLeft())
        
    def connect_session_signals(self):
        """Connect to session manager signals"""
        session_manager.user_logged_in.connect(self.on_user_logged_in)
        session_manager.mfa_completed.connect(self.on_mfa_completed)
        session_manager.user_logged_out.connect(self.on_user_logged_out)
        session_manager.session_expired.connect(self.on_session_expired)
    
    def on_user_logged_in(self, user_info):
        """Handle user login event"""
        self.update_status(f"Logged in as: {user_info.get('email', 'Unknown')}")
        
    def on_mfa_completed(self):
        """Handle MFA completion event"""
        self.update_status("MFA completed - Full access granted")
        
    def on_user_logged_out(self):
        """Handle user logout event"""
        self.update_status("User logged out")
        
    def on_session_expired(self):
        """Handle session expiration event"""
        self.update_status("Session expired")
        
    def update_status(self, message):
        """Update status bar message"""
        self.status_bar.showMessage(message)
        
    def log_action(self, action, status='success', details=None):
        """Log user action"""
        user_id = session_manager.get_user_id()
        security_logger.log_activity(
            user_id=user_id,
            action=action,
            status=status,
            details=details
        )
        
    def show_in_status(self, message, timeout=3000):
        """Show temporary message in status bar"""
        self.status_bar.showMessage(message, timeout)
        
    def closeEvent(self, event):
        """Handle window close event"""
        self.window_closed.emit()
        super().closeEvent(event) 
