"""
LoginWindow - Main authentication entry point for SecurityApp

This module provides the primary login interface that users see when starting
the application. It integrates with the existing auth.py module through the
AuthController and handles the complete authentication flow including MFA.
"""

from PyQt5.QtWidgets import (QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, 
                             QPushButton, QCheckBox, QFrame, QSpacerItem, QSizePolicy)
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QFont, QPixmap

from ..base.base_window import BaseWindow
from ..controllers.auth_controller import AuthController
from ..utils.message_boxes import MessageBoxes
from .registration_dialog import RegistrationDialog
from .mfa_dialog import MFAVerificationDialog
from .account_recovery_dialog import AccountRecoveryDialog


class LoginWindow(BaseWindow):
    """
    Main login window for SecurityApp authentication.
    
    This window handles:
    - User authentication with username/passphrase
    - Navigation to registration for new users
    - Account recovery for locked accounts
    - Integration with MFA verification flow
    - Session management and main application launch
    """
    
    # Signals for authentication flow
    authentication_successful = pyqtSignal(str)  # username
    show_main_application = pyqtSignal()
    
    def __init__(self):
        super().__init__()
        self.auth_controller = AuthController()
        self.setup_ui()
        self.setup_connections()
        
    def setup_ui(self):
        """Setup the login window UI with professional styling."""
        self.setWindowTitle("SecurityApp - Login")
        self.setFixedSize(450, 500)
        self.center_window()
        
        # Main layout
        main_layout = QVBoxLayout()
        main_layout.setSpacing(20)
        main_layout.setContentsMargins(40, 40, 40, 40)
        
        # Header section
        header_layout = self.create_header_section()
        main_layout.addLayout(header_layout)
        
        # Login form section
        form_layout = self.create_login_form()
        main_layout.addLayout(form_layout)
        
        # Action buttons section
        button_layout = self.create_action_buttons()
        main_layout.addLayout(button_layout)
        
        # Footer section
        footer_layout = self.create_footer_section()
        main_layout.addLayout(footer_layout)
        
        # Add flexible space
        main_layout.addStretch()
        
        # Set main layout
        central_widget = QFrame()
        central_widget.setLayout(main_layout)
        self.setCentralWidget(central_widget)
        
    def create_header_section(self):
        """Create the header section with title and subtitle."""
        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignCenter)
        
        # Main title
        title_label = QLabel("SecurityApp")
        title_font = QFont()
        title_font.setPointSize(24)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setStyleSheet("color: #2c3e50; margin-bottom: 5px;")
        layout.addWidget(title_label)
        
        # Subtitle
        subtitle_label = QLabel("Secure File Management & Digital Signatures")
        subtitle_font = QFont()
        subtitle_font.setPointSize(11)
        subtitle_label.setFont(subtitle_font)
        subtitle_label.setAlignment(Qt.AlignCenter)
        subtitle_label.setStyleSheet("color: #7f8c8d; margin-bottom: 20px;")
        layout.addWidget(subtitle_label)
        
        return layout
        
    def create_login_form(self):
        """Create the main login form with username and passphrase fields."""
        layout = QVBoxLayout()
        layout.setSpacing(15)
        
        # Username field
        username_label = QLabel("Username:")
        username_label.setStyleSheet("font-weight: bold; color: #2c3e50;")
        layout.addWidget(username_label)
        
        self.username_field = QLineEdit()
        self.username_field.setPlaceholderText("Enter your username")
        self.username_field.setStyleSheet("""
            QLineEdit {
                padding: 10px;
                border: 2px solid #bdc3c7;
                border-radius: 5px;
                font-size: 12px;
                background-color: white;
            }
            QLineEdit:focus {
                border-color: #3498db;
            }
        """)
        layout.addWidget(self.username_field)
        
        # Passphrase field
        passphrase_label = QLabel("Passphrase:")
        passphrase_label.setStyleSheet("font-weight: bold; color: #2c3e50;")
        layout.addWidget(passphrase_label)
        
        self.passphrase_field = QLineEdit()
        self.passphrase_field.setPlaceholderText("Enter your passphrase")
        self.passphrase_field.setEchoMode(QLineEdit.Password)
        self.passphrase_field.setStyleSheet("""
            QLineEdit {
                padding: 10px;
                border: 2px solid #bdc3c7;
                border-radius: 5px;
                font-size: 12px;
                background-color: white;
            }
            QLineEdit:focus {
                border-color: #3498db;
            }
        """)
        layout.addWidget(self.passphrase_field)
        
        # Remember me checkbox
        self.remember_checkbox = QCheckBox("Remember me")
        self.remember_checkbox.setStyleSheet("color: #2c3e50; margin-top: 5px;")
        layout.addWidget(self.remember_checkbox)
        
        return layout
        
    def create_action_buttons(self):
        """Create the main action buttons for login and navigation."""
        layout = QVBoxLayout()
        layout.setSpacing(10)
        
        # Login button
        self.login_button = QPushButton("Login")
        self.login_button.setStyleSheet("""
            QPushButton {
                background-color: #3498db;
                color: white;
                border: none;
                padding: 12px;
                border-radius: 5px;
                font-size: 13px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
            QPushButton:pressed {
                background-color: #21618c;
            }
            QPushButton:disabled {
                background-color: #bdc3c7;
            }
        """)
        layout.addWidget(self.login_button)
        
        return layout
        
    def create_footer_section(self):
        """Create the footer section with additional options."""
        layout = QVBoxLayout()
        layout.setSpacing(10)
        
        # Separator line
        separator = QFrame()
        separator.setFrameShape(QFrame.HLine)
        separator.setFrameShadow(QFrame.Sunken)
        separator.setStyleSheet("color: #bdc3c7;")
        layout.addWidget(separator)
        
        # Additional options
        options_layout = QHBoxLayout()
        
        # Register button
        self.register_button = QPushButton("Create Account")
        self.register_button.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                color: #3498db;
                border: 2px solid #3498db;
                padding: 8px 16px;
                border-radius: 5px;
                font-size: 11px;
            }
            QPushButton:hover {
                background-color: #3498db;
                color: white;
            }
        """)
        options_layout.addWidget(self.register_button)
        
        # Recovery button
        self.recovery_button = QPushButton("Account Recovery")
        self.recovery_button.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                color: #e74c3c;
                border: 2px solid #e74c3c;
                padding: 8px 16px;
                border-radius: 5px;
                font-size: 11px;
            }
            QPushButton:hover {
                background-color: #e74c3c;
                color: white;
            }
        """)
        options_layout.addWidget(self.recovery_button)
        
        layout.addLayout(options_layout)
        
        return layout
        
    def setup_connections(self):
        """Setup signal/slot connections for the login window."""
        # Button connections
        self.login_button.clicked.connect(self.handle_login)
        self.register_button.clicked.connect(self.show_registration)
        self.recovery_button.clicked.connect(self.show_recovery)
        
        # Enter key connections
        self.username_field.returnPressed.connect(self.handle_login)
        self.passphrase_field.returnPressed.connect(self.handle_login)
        
        # Real-time validation
        self.username_field.textChanged.connect(self.validate_form)
        self.passphrase_field.textChanged.connect(self.validate_form)
        
    def validate_form(self):
        """Validate form fields and enable/disable login button."""
        username = self.username_field.text().strip()
        passphrase = self.passphrase_field.text()
        
        # Enable login button only if both fields have content
        self.login_button.setEnabled(bool(username and passphrase))
        
    def handle_login(self):
        """Handle the login process with MFA verification."""
        if not self.login_button.isEnabled():
            return
            
        username = self.username_field.text().strip()
        passphrase = self.passphrase_field.text()
        
        if not username or not passphrase:
            MessageBoxes.warning(self, "Validation Error", 
                                "Please enter both username and passphrase.")
            return
            
        # Disable UI during authentication
        self.set_ui_enabled(False)
        
        try:
            # Attempt initial authentication
            auth_result = self.auth_controller.authenticate_user(username, passphrase)
            
            if auth_result['success']:
                # Check if MFA is required
                if auth_result.get('requires_mfa', False):
                    self.handle_mfa_verification(username, auth_result.get('mfa_type'))
                else:
                    # Direct login success
                    self.complete_authentication(username)
            else:
                # Handle authentication failure
                error_msg = auth_result.get('message', 'Authentication failed')
                
                if 'locked' in error_msg.lower():
                    MessageBoxes.warning(self, "Account Locked", 
                                       f"{error_msg}\n\nPlease contact administrator or use account recovery.")
                else:
                    MessageBoxes.show_error(self, "Authentication Failed", error_msg)
                    
        except Exception as e:
            MessageBoxes.show_error(self, "Authentication Error", 
                             f"An error occurred during authentication: {str(e)}")
        finally:
            self.set_ui_enabled(True)
            
    def handle_mfa_verification(self, username, mfa_type):
        """Handle MFA verification process."""
        try:
            mfa_dialog = MFAVerificationDialog(username, mfa_type, self.auth_controller, self)
            
            if mfa_dialog.exec_() == mfa_dialog.Accepted:
                # MFA verification successful
                self.complete_authentication(username)
            else:
                # MFA verification failed or cancelled
                MessageBoxes.info(self, "Authentication Cancelled", 
                                "MFA verification was cancelled.")
                
        except Exception as e:
            MessageBoxes.show_error(self, "MFA Error", 
                             f"An error occurred during MFA verification: {str(e)}")
            
    def complete_authentication(self, username):
        """Complete the authentication process and launch main application."""
        try:
            # Store authentication state
            self.auth_controller.set_current_user(username)
            
            # Emit success signals
            self.authentication_successful.emit(username)
            
            # Clear sensitive fields
            self.passphrase_field.clear()
            
            # Hide login window and show main application
            self.hide()
            self.show_main_application.emit()
            
        except Exception as e:
            MessageBoxes.show_error(self, "Authentication Error", 
                             f"Failed to complete authentication: {str(e)}")
            
    def show_registration(self):
        """Show the registration dialog for new users."""
        try:
            registration_dialog = RegistrationDialog(self.auth_controller, self)
            
            if registration_dialog.exec_() == registration_dialog.Accepted:
                MessageBoxes.info(self, "Registration Successful", 
                                "Account created successfully! You can now log in.")
                # Optionally pre-fill username
                if hasattr(registration_dialog, 'username'):
                    self.username_field.setText(registration_dialog.username)
                    
        except Exception as e:
            MessageBoxes.show_error(self, "Registration Error", 
                             f"An error occurred during registration: {str(e)}")
            
    def show_recovery(self):
        """Show the account recovery dialog."""
        try:
            recovery_dialog = AccountRecoveryDialog(self.auth_controller, self)
            recovery_dialog.exec_()
            
        except Exception as e:
            MessageBoxes.show_error(self, "Recovery Error", 
                             f"An error occurred during account recovery: {str(e)}")
            
    def set_ui_enabled(self, enabled):
        """Enable or disable UI elements during processing."""
        self.username_field.setEnabled(enabled)
        self.passphrase_field.setEnabled(enabled)
        self.login_button.setEnabled(enabled and bool(
            self.username_field.text().strip() and self.passphrase_field.text()))
        self.register_button.setEnabled(enabled)
        self.recovery_button.setEnabled(enabled)
        self.remember_checkbox.setEnabled(enabled)
        
    def reset_form(self):
        """Reset the login form to initial state."""
        self.username_field.clear()
        self.passphrase_field.clear()
        self.remember_checkbox.setChecked(False)
        self.username_field.setFocus()
        
    def show_window(self):
        """Show the login window and reset form."""
        self.reset_form()
        self.show()
        self.raise_()
        self.activateWindow() 
