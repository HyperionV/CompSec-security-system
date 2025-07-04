"""
AccountRecoveryDialog - Account recovery interface for SecurityApp

This module provides the account recovery dialog for users who have forgotten their
password or need to unlock their account. It integrates with the existing auth.py
module through the AuthController.
"""

from PyQt5.QtWidgets import (QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, 
                             QPushButton, QFrame, QProgressBar, QTextEdit, 
                             QSpacerItem, QSizePolicy, QGroupBox)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QThread, pyqtSlot
from PyQt5.QtGui import QFont, QPixmap

from ..base.base_dialog import BaseDialog
from ..utils.message_boxes import MessageBoxes


class AccountRecoveryWorker(QThread):
    """Worker thread for account recovery operations."""
    
    recovery_completed = pyqtSignal(bool, str)  # success, message
    lockout_checked = pyqtSignal(bool, str, int)  # is_locked, message, remaining_time
    
    def __init__(self, auth_controller, operation, **kwargs):
        super().__init__()
        self.auth_controller = auth_controller
        self.operation = operation
        self.kwargs = kwargs
        
    def run(self):
        """Execute the recovery operation."""
        try:
            if self.operation == "check_lockout":
                email = self.kwargs.get('email')
                is_locked, message, remaining_time = self.auth_controller.check_account_lockout(email)
                self.lockout_checked.emit(is_locked, message, remaining_time)
                
            elif self.operation == "recover_account":
                email = self.kwargs.get('email')
                recovery_code = self.kwargs.get('recovery_code')
                new_password = self.kwargs.get('new_password')
                
                success, message = self.auth_controller.recover_account_with_code(
                    email, recovery_code, new_password
                )
                self.recovery_completed.emit(success, message)
                
        except Exception as e:
            if self.operation == "check_lockout":
                self.lockout_checked.emit(False, f"Error checking account: {str(e)}", 0)
            else:
                self.recovery_completed.emit(False, f"Recovery failed: {str(e)}")


class AccountRecoveryDialog(BaseDialog):
    """
    Account recovery dialog for password reset and account unlock.
    
    This dialog handles:
    - Account lockout status checking
    - Recovery code verification
    - New password setup with strength validation
    - Integration with existing auth.py module
    """
    
    # Signals for recovery flow
    recovery_completed = pyqtSignal(bool, str)  # success, message
    
    def __init__(self, auth_controller, parent=None):
        self.auth_controller = auth_controller
        self.recovery_worker = None
        
        super().__init__(parent)
        self.setup_ui()
        self.setup_connections()
        
    def setup_ui(self):
        """Setup the account recovery dialog UI."""
        self.setWindowTitle("Account Recovery")
        self.setFixedSize(600, 700)
        
        layout = QVBoxLayout()
        layout.setSpacing(20)
        layout.setContentsMargins(30, 30, 30, 30)
        
        # Header
        header_layout = self.create_header()
        layout.addLayout(header_layout)
        
        # Account identification section
        account_group = self.create_account_section()
        layout.addWidget(account_group)
        
        # Recovery code section
        recovery_group = self.create_recovery_section()
        layout.addWidget(recovery_group)
        
        # New password section
        password_group = self.create_password_section()
        layout.addWidget(password_group)
        
        # Progress section
        progress_group = self.create_progress_section()
        layout.addWidget(progress_group)
        
        # Action buttons
        button_layout = self.create_action_buttons()
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
        
    def create_header(self):
        """Create the header section."""
        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignCenter)
        
        title_label = QLabel("Account Recovery")
        title_font = QFont()
        title_font.setPointSize(18)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setStyleSheet("color: #2c3e50; margin-bottom: 10px;")
        layout.addWidget(title_label)
        
        subtitle_label = QLabel("Recover your account using your recovery code")
        subtitle_label.setAlignment(Qt.AlignCenter)
        subtitle_label.setStyleSheet("color: #7f8c8d; margin-bottom: 20px;")
        layout.addWidget(subtitle_label)
        
        # Instructions
        instructions = QLabel("""
1. Enter your registered email address
2. Check if your account is locked
3. Enter your recovery code (saved during registration)
4. Create a new strong password
5. Complete recovery process
        """.strip())
        instructions.setStyleSheet("color: #34495e; background-color: #ecf0f1; padding: 15px; border-radius: 5px;")
        layout.addWidget(instructions)
        
        return layout
        
    def create_account_section(self):
        """Create account identification section."""
        group = QGroupBox("Account Identification")
        group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 2px solid #bdc3c7;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
            }
        """)
        
        layout = QVBoxLayout()
        layout.setSpacing(15)
        
        # Email input
        email_label = QLabel("Email Address:")
        email_label.setStyleSheet("font-weight: bold; color: #2c3e50;")
        layout.addWidget(email_label)
        
        self.email_field = QLineEdit()
        self.email_field.setPlaceholderText("Enter your registered email address")
        self.email_field.setStyleSheet("""
            QLineEdit {
                padding: 12px;
                border: 2px solid #bdc3c7;
                border-radius: 5px;
                font-size: 14px;
                background-color: white;
            }
            QLineEdit:focus {
                border-color: #3498db;
            }
        """)
        layout.addWidget(self.email_field)
        
        # Check account button
        self.check_account_btn = QPushButton("Check Account Status")
        self.check_account_btn.setStyleSheet("""
            QPushButton {
                background-color: #3498db;
                color: white;
                border: none;
                padding: 12px;
                border-radius: 5px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
            QPushButton:pressed {
                background-color: #21618c;
            }
            QPushButton:disabled {
                background-color: #bdc3c7;
                color: #7f8c8d;
            }
        """)
        layout.addWidget(self.check_account_btn)
        
        # Account status display
        self.account_status_label = QLabel("")
        self.account_status_label.setStyleSheet("color: #7f8c8d; font-style: italic;")
        layout.addWidget(self.account_status_label)
        
        group.setLayout(layout)
        return group
        
    def create_recovery_section(self):
        """Create recovery code section."""
        group = QGroupBox("Recovery Code")
        group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 2px solid #bdc3c7;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
            }
        """)
        
        layout = QVBoxLayout()
        layout.setSpacing(15)
        
        # Recovery code input
        code_label = QLabel("Recovery Code:")
        code_label.setStyleSheet("font-weight: bold; color: #2c3e50;")
        layout.addWidget(code_label)
        
        code_help = QLabel("Enter the 16-character recovery code you saved during registration")
        code_help.setStyleSheet("color: #7f8c8d; font-size: 12px;")
        layout.addWidget(code_help)
        
        self.recovery_code_field = QLineEdit()
        self.recovery_code_field.setPlaceholderText("XXXX-XXXX-XXXX-XXXX")
        self.recovery_code_field.setMaxLength(16)
        self.recovery_code_field.setStyleSheet("""
            QLineEdit {
                padding: 12px;
                border: 2px solid #bdc3c7;
                border-radius: 5px;
                font-size: 16px;
                font-family: monospace;
                text-transform: uppercase;
                background-color: white;
            }
            QLineEdit:focus {
                border-color: #3498db;
            }
        """)
        layout.addWidget(self.recovery_code_field)
        
        group.setLayout(layout)
        return group
        
    def create_password_section(self):
        """Create new password section."""
        group = QGroupBox("New Password")
        group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 2px solid #bdc3c7;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
            }
        """)
        
        layout = QVBoxLayout()
        layout.setSpacing(15)
        
        # New password input
        password_label = QLabel("New Password:")
        password_label.setStyleSheet("font-weight: bold; color: #2c3e50;")
        layout.addWidget(password_label)
        
        self.new_password_field = QLineEdit()
        self.new_password_field.setPlaceholderText("Enter new strong password")
        self.new_password_field.setEchoMode(QLineEdit.Password)
        self.new_password_field.setStyleSheet("""
            QLineEdit {
                padding: 12px;
                border: 2px solid #bdc3c7;
                border-radius: 5px;
                font-size: 14px;
                background-color: white;
            }
            QLineEdit:focus {
                border-color: #3498db;
            }
        """)
        layout.addWidget(self.new_password_field)
        
        # Confirm password input
        confirm_label = QLabel("Confirm New Password:")
        confirm_label.setStyleSheet("font-weight: bold; color: #2c3e50;")
        layout.addWidget(confirm_label)
        
        self.confirm_password_field = QLineEdit()
        self.confirm_password_field.setPlaceholderText("Confirm new password")
        self.confirm_password_field.setEchoMode(QLineEdit.Password)
        self.confirm_password_field.setStyleSheet("""
            QLineEdit {
                padding: 12px;
                border: 2px solid #bdc3c7;
                border-radius: 5px;
                font-size: 14px;
                background-color: white;
            }
            QLineEdit:focus {
                border-color: #3498db;
            }
        """)
        layout.addWidget(self.confirm_password_field)
        
        # Password strength indicator
        self.password_strength_label = QLabel("")
        self.password_strength_label.setStyleSheet("color: #7f8c8d; font-size: 12px;")
        layout.addWidget(self.password_strength_label)
        
        # Password requirements
        requirements = QLabel("""
Password Requirements:
• At least 8 characters long
• Contains uppercase and lowercase letters
• Contains at least one number
• Contains at least one special character (!@#$%^&*(),.?":{}|<>)
        """.strip())
        requirements.setStyleSheet("color: #34495e; font-size: 11px; background-color: #f8f9fa; padding: 10px; border-radius: 3px;")
        layout.addWidget(requirements)
        
        group.setLayout(layout)
        return group
        
    def create_progress_section(self):
        """Create progress section."""
        group = QGroupBox("Recovery Progress")
        group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 2px solid #bdc3c7;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
            }
        """)
        
        layout = QVBoxLayout()
        layout.setSpacing(10)
        
        self.progress_label = QLabel("Enter account information to begin recovery")
        self.progress_label.setStyleSheet("color: #7f8c8d;")
        layout.addWidget(self.progress_label)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 2px solid #bdc3c7;
                border-radius: 5px;
                text-align: center;
            }
            QProgressBar::chunk {
                background-color: #3498db;
                border-radius: 3px;
            }
        """)
        layout.addWidget(self.progress_bar)
        
        group.setLayout(layout)
        return group
        
    def create_action_buttons(self):
        """Create action buttons."""
        layout = QHBoxLayout()
        layout.setSpacing(15)
        
        # Add spacer
        layout.addItem(QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum))
        
        # Cancel button
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setStyleSheet("""
            QPushButton {
                background-color: #95a5a6;
                color: white;
                border: none;
                padding: 12px 24px;
                border-radius: 5px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #7f8c8d;
            }
            QPushButton:pressed {
                background-color: #6c7b7d;
            }
        """)
        layout.addWidget(self.cancel_btn)
        
        # Recover account button
        self.recover_btn = QPushButton("Recover Account")
        self.recover_btn.setEnabled(False)
        self.recover_btn.setStyleSheet("""
            QPushButton {
                background-color: #27ae60;
                color: white;
                border: none;
                padding: 12px 24px;
                border-radius: 5px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #229954;
            }
            QPushButton:pressed {
                background-color: #1e8449;
            }
            QPushButton:disabled {
                background-color: #bdc3c7;
                color: #7f8c8d;
            }
        """)
        layout.addWidget(self.recover_btn)
        
        return layout
        
    def setup_connections(self):
        """Setup signal connections."""
        # Button connections
        self.check_account_btn.clicked.connect(self.check_account_status)
        self.recover_btn.clicked.connect(self.initiate_recovery)
        self.cancel_btn.clicked.connect(self.reject)
        
        # Field validation connections
        self.email_field.textChanged.connect(self.validate_inputs)
        self.recovery_code_field.textChanged.connect(self.validate_inputs)
        self.new_password_field.textChanged.connect(self.validate_password)
        self.confirm_password_field.textChanged.connect(self.validate_password)
        
    def validate_inputs(self):
        """Validate input fields and enable/disable buttons."""
        email_valid = len(self.email_field.text().strip()) > 0
        code_valid = len(self.recovery_code_field.text().strip()) == 16
        password_valid = self.validate_password_strength()
        passwords_match = (self.new_password_field.text() == 
                          self.confirm_password_field.text())
        
        self.check_account_btn.setEnabled(email_valid)
        self.recover_btn.setEnabled(
            email_valid and code_valid and password_valid and passwords_match
        )
        
    def validate_password(self):
        """Validate password strength and matching."""
        password = self.new_password_field.text()
        confirm = self.confirm_password_field.text()
        
        # Check password strength
        strength_valid = self.validate_password_strength()
        
        # Check password matching
        if confirm and password != confirm:
            self.password_strength_label.setText("❌ Passwords do not match")
            self.password_strength_label.setStyleSheet("color: #e74c3c; font-size: 12px;")
        elif strength_valid and confirm and password == confirm:
            self.password_strength_label.setText("✅ Passwords match and are strong")
            self.password_strength_label.setStyleSheet("color: #27ae60; font-size: 12px;")
        
        self.validate_inputs()
        
    def validate_password_strength(self):
        """Check password strength against requirements."""
        password = self.new_password_field.text()
        
        if not password:
            return False
            
        # Use auth controller to validate
        try:
            success, message = self.auth_controller.validate_password_strength(password)
            if not success:
                if not self.confirm_password_field.text():  # Only show strength errors if not typing confirm
                    self.password_strength_label.setText(f"❌ {message}")
                    self.password_strength_label.setStyleSheet("color: #e74c3c; font-size: 12px;")
                return False
            else:
                if not self.confirm_password_field.text():
                    self.password_strength_label.setText("✅ Strong password")
                    self.password_strength_label.setStyleSheet("color: #27ae60; font-size: 12px;")
                return True
        except:
            return False
            
    def check_account_status(self):
        """Check account lockout status."""
        email = self.email_field.text().strip()
        if not email:
            MessageBoxes.warning(self, "Invalid Input", "Please enter your email address.")
            return
            
        # Start worker thread for checking account status
        self.check_account_btn.setEnabled(False)
        self.progress_label.setText("Checking account status...")
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate progress
        
        self.recovery_worker = AccountRecoveryWorker(
            self.auth_controller, 
            "check_lockout",
            email=email
        )
        self.recovery_worker.lockout_checked.connect(self.handle_lockout_result)
        self.recovery_worker.start()
        
    @pyqtSlot(bool, str, int)
    def handle_lockout_result(self, is_locked, message, remaining_time):
        """Handle account lockout check result."""
        self.progress_bar.setVisible(False)
        self.check_account_btn.setEnabled(True)
        
        if is_locked:
            self.account_status_label.setText(f"⚠️ {message}")
            self.account_status_label.setStyleSheet("color: #e74c3c; font-weight: bold;")
            self.progress_label.setText("Account is locked. Please wait before attempting recovery.")
        else:
            self.account_status_label.setText("✅ Account is ready for recovery")
            self.account_status_label.setStyleSheet("color: #27ae60; font-weight: bold;")
            self.progress_label.setText("Account verified. Enter recovery code and new password.")
            
        self.validate_inputs()
        
    def initiate_recovery(self):
        """Initiate the account recovery process."""
        email = self.email_field.text().strip()
        recovery_code = self.recovery_code_field.text().strip().upper()
        new_password = self.new_password_field.text()
        confirm_password = self.confirm_password_field.text()
        
        # Final validation
        if not email or not recovery_code or not new_password:
            MessageBoxes.warning(self, "Incomplete Information", 
                               "Please fill in all required fields.")
            return
            
        if new_password != confirm_password:
            MessageBoxes.warning(self, "Password Mismatch", 
                               "Passwords do not match.")
            return
            
        # Confirm recovery action
        reply = MessageBoxes.confirmation(
            self, "Confirm Account Recovery",
            f"Are you sure you want to recover the account for {email}?\n\n"
            "This will:\n"
            "• Reset your password\n"
            "• Invalidate existing RSA keys for security\n"
            "• Require generating new keys after recovery\n\n"
            "This action cannot be undone."
        )
        
        if not reply:
            return
            
        # Start recovery process
        self.recover_btn.setEnabled(False)
        self.cancel_btn.setEnabled(False)
        self.progress_label.setText("Recovering account...")
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate progress
        
        self.recovery_worker = AccountRecoveryWorker(
            self.auth_controller,
            "recover_account",
            email=email,
            recovery_code=recovery_code,
            new_password=new_password
        )
        self.recovery_worker.recovery_completed.connect(self.handle_recovery_result)
        self.recovery_worker.start()
        
    @pyqtSlot(bool, str)
    def handle_recovery_result(self, success, message):
        """Handle recovery result."""
        self.progress_bar.setVisible(False)
        self.recover_btn.setEnabled(True)
        self.cancel_btn.setEnabled(True)
        
        if success:
            self.progress_label.setText("✅ Account recovered successfully!")
            MessageBoxes.info(
                self, "Recovery Successful",
                f"Account recovery completed successfully!\n\n{message}\n\n"
                "You can now log in with your new password."
            )
            self.recovery_completed.emit(True, message)
            self.accept()
        else:
            self.progress_label.setText("❌ Recovery failed")
            MessageBoxes.show_error(self, "Recovery Failed", f"Account recovery failed:\n\n{message}")
            self.recovery_completed.emit(False, message)
            
    def closeEvent(self, event):
        """Handle dialog close event."""
        # Stop any running worker threads
        if self.recovery_worker and self.recovery_worker.isRunning():
            self.recovery_worker.terminate()
            self.recovery_worker.wait()
        event.accept() 
