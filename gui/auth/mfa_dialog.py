"""
MFAVerificationDialog - Multi-Factor Authentication interface for SecurityApp

This module provides the MFA verification dialog for both email OTP and TOTP
(Google Authenticator) authentication methods. It integrates with the existing
mfa.py module through the AuthController.
"""

from PyQt5.QtWidgets import (QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, 
                             QPushButton, QRadioButton, QButtonGroup, QFrame,
                             QTabWidget, QWidget, QTextEdit, QSpacerItem, QSizePolicy)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QFont, QPixmap

from ..base.base_dialog import BaseDialog
from ..base.common_widgets import QRCodeDisplayWidget
from ..utils.message_boxes import MessageBoxes


class MFAVerificationDialog(BaseDialog):
    """
    Multi-Factor Authentication verification dialog.
    
    This dialog handles:
    - Email OTP verification with resend functionality
    - TOTP (Google Authenticator) verification with QR code setup
    - Real-time code validation
    - Timeout handling and retry logic
    - Integration with existing mfa.py module
    """
    
    # Signals for MFA flow
    mfa_completed = pyqtSignal(str)  # mfa_type
    
    def __init__(self, username, mfa_type, auth_controller, parent=None):
        self.username = username
        self.mfa_type = mfa_type  # 'email_otp' or 'totp' or 'both'
        self.auth_controller = auth_controller
        self.verification_successful = False
        
        super().__init__(parent)
        self.setup_ui()
        self.setup_connections()
        self.initialize_mfa()
        
    def setup_ui(self):
        """Setup the MFA verification dialog UI."""
        self.setWindowTitle("Multi-Factor Authentication")
        self.setFixedSize(500, 600)
        
        layout = QVBoxLayout()
        layout.setSpacing(20)
        layout.setContentsMargins(30, 30, 30, 30)
        
        # Header
        header_layout = self.create_header()
        layout.addLayout(header_layout)
        
        # MFA method selection or single method display
        if self.mfa_type == 'both':
            self.create_tabbed_interface(layout)
        elif self.mfa_type == 'email_otp':
            self.create_email_otp_interface(layout)
        elif self.mfa_type == 'totp':
            self.create_totp_interface(layout)
        else:
            # Default to email OTP
            self.create_email_otp_interface(layout)
            
        # Action buttons
        button_layout = self.create_action_buttons()
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
        
    def create_header(self):
        """Create the header section."""
        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignCenter)
        
        title_label = QLabel("Multi-Factor Authentication")
        title_font = QFont()
        title_font.setPointSize(18)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setStyleSheet("color: #2c3e50; margin-bottom: 10px;")
        layout.addWidget(title_label)
        
        subtitle_label = QLabel(f"Additional verification required for {self.username}")
        subtitle_label.setAlignment(Qt.AlignCenter)
        subtitle_label.setStyleSheet("color: #7f8c8d; margin-bottom: 20px;")
        layout.addWidget(subtitle_label)
        
        return layout
        
    def create_tabbed_interface(self, parent_layout):
        """Create tabbed interface for multiple MFA methods."""
        self.tab_widget = QTabWidget()
        self.tab_widget.setStyleSheet("""
            QTabWidget::pane {
                border: 2px solid #bdc3c7;
                border-radius: 5px;
                background-color: white;
            }
            QTabBar::tab {
                background-color: #ecf0f1;
                padding: 10px 20px;
                margin-right: 2px;
                border-top-left-radius: 5px;
                border-top-right-radius: 5px;
            }
            QTabBar::tab:selected {
                background-color: white;
                border-bottom: 2px solid white;
            }
        """)
        
        # Email OTP tab
        email_tab = QWidget()
        email_layout = QVBoxLayout()
        self.create_email_otp_content(email_layout)
        email_tab.setLayout(email_layout)
        self.tab_widget.addTab(email_tab, "Email Verification")
        
        # TOTP tab
        totp_tab = QWidget()
        totp_layout = QVBoxLayout()
        self.create_totp_content(totp_layout)
        totp_tab.setLayout(totp_layout)
        self.tab_widget.addTab(totp_tab, "Authenticator App")
        
        parent_layout.addWidget(self.tab_widget)
        
    def create_email_otp_interface(self, parent_layout):
        """Create standalone email OTP interface."""
        frame = QFrame()
        frame.setFrameShape(QFrame.Box)
        frame.setStyleSheet("border: 2px solid #bdc3c7; border-radius: 5px; background-color: white;")
        
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 20)
        self.create_email_otp_content(layout)
        frame.setLayout(layout)
        
        parent_layout.addWidget(frame)
        
    def create_totp_interface(self, parent_layout):
        """Create standalone TOTP interface."""
        frame = QFrame()
        frame.setFrameShape(QFrame.Box)
        frame.setStyleSheet("border: 2px solid #bdc3c7; border-radius: 5px; background-color: white;")
        
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 20)
        self.create_totp_content(layout)
        frame.setLayout(layout)
        
        parent_layout.addWidget(frame)
        
    def create_email_otp_content(self, layout):
        """Create email OTP verification content."""
        # Email OTP section title
        title_label = QLabel("Email Verification Code")
        title_font = QFont()
        title_font.setBold(True)
        title_font.setPointSize(14)
        title_label.setFont(title_font)
        title_label.setStyleSheet("color: #2c3e50; margin-bottom: 15px;")
        layout.addWidget(title_label)
        
        # Email sent confirmation
        self.email_status_label = QLabel("Sending verification code...")
        self.email_status_label.setStyleSheet("color: #7f8c8d; margin-bottom: 15px;")
        layout.addWidget(self.email_status_label)
        
        # OTP input field
        otp_label = QLabel("Enter verification code:")
        otp_label.setStyleSheet("font-weight: bold; color: #2c3e50;")
        layout.addWidget(otp_label)
        
        self.email_otp_field = QLineEdit()
        self.email_otp_field.setPlaceholderText("Enter 6-digit code")
        self.email_otp_field.setMaxLength(6)
        self.email_otp_field.setStyleSheet("""
            QLineEdit {
                padding: 12px;
                border: 2px solid #bdc3c7;
                border-radius: 5px;
                font-size: 16px;
                font-family: monospace;
                text-align: center;
                background-color: white;
            }
            QLineEdit:focus {
                border-color: #3498db;
            }
        """)
        layout.addWidget(self.email_otp_field)
        
        # Resend button
        resend_layout = QHBoxLayout()
        resend_layout.addStretch()
        
        self.resend_button = QPushButton("Resend Code")
        self.resend_button.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                color: #3498db;
                border: 1px solid #3498db;
                padding: 8px 16px;
                border-radius: 5px;
                font-size: 11px;
            }
            QPushButton:hover {
                background-color: #3498db;
                color: white;
            }
            QPushButton:disabled {
                color: #bdc3c7;
                border-color: #bdc3c7;
            }
        """)
        resend_layout.addWidget(self.resend_button)
        resend_layout.addStretch()
        
        layout.addLayout(resend_layout)
        
        # Countdown timer label
        self.countdown_label = QLabel("")
        self.countdown_label.setAlignment(Qt.AlignCenter)
        self.countdown_label.setStyleSheet("color: #7f8c8d; font-size: 11px;")
        layout.addWidget(self.countdown_label)
        
    def create_totp_content(self, layout):
        """Create TOTP verification content."""
        # TOTP section title
        title_label = QLabel("Authenticator App")
        title_font = QFont()
        title_font.setBold(True)
        title_font.setPointSize(14)
        title_label.setFont(title_font)
        title_label.setStyleSheet("color: #2c3e50; margin-bottom: 15px;")
        layout.addWidget(title_label)
        
        # Check if TOTP is already set up
        try:
            totp_setup = self.auth_controller.check_totp_setup(self.username)
            
            if not totp_setup.get('is_setup', False):
                self.create_totp_setup_content(layout)
            else:
                self.create_totp_verify_content(layout)
                
        except Exception as e:
            # Default to setup if we can't determine status
            self.create_totp_setup_content(layout)
            
    def create_totp_setup_content(self, layout):
        """Create TOTP setup content with QR code."""
        # Setup instructions
        instructions = QLabel("Scan the QR code below with your authenticator app:")
        instructions.setStyleSheet("color: #7f8c8d; margin-bottom: 15px;")
        layout.addWidget(instructions)
        
        # QR Code display
        try:
            qr_data = self.auth_controller.generate_totp_qr(self.username)
            
            if qr_data.get('success'):
                # QR Code widget
                self.qr_widget = QRCodeDisplayWidget()
                self.qr_widget.display_qr_code(qr_data['qr_code_data'])
                layout.addWidget(self.qr_widget)
                
                # Manual entry option
                manual_label = QLabel(f"Manual entry key: {qr_data.get('secret_key', 'N/A')}")
                manual_label.setStyleSheet("font-family: monospace; color: #7f8c8d; font-size: 10px;")
                manual_label.setWordWrap(True)
                layout.addWidget(manual_label)
            else:
                error_label = QLabel("Failed to generate QR code")
                error_label.setStyleSheet("color: #e74c3c;")
                layout.addWidget(error_label)
                
        except Exception as e:
            error_label = QLabel(f"Error generating QR code: {str(e)}")
            error_label.setStyleSheet("color: #e74c3c;")
            layout.addWidget(error_label)
            
        # Verification input for setup
        verify_label = QLabel("Enter code from your app to confirm setup:")
        verify_label.setStyleSheet("font-weight: bold; color: #2c3e50; margin-top: 15px;")
        layout.addWidget(verify_label)
        
        self.totp_setup_field = QLineEdit()
        self.totp_setup_field.setPlaceholderText("Enter 6-digit code")
        self.totp_setup_field.setMaxLength(6)
        self.totp_setup_field.setStyleSheet("""
            QLineEdit {
                padding: 12px;
                border: 2px solid #bdc3c7;
                border-radius: 5px;
                font-size: 16px;
                font-family: monospace;
                text-align: center;
                background-color: white;
            }
            QLineEdit:focus {
                border-color: #3498db;
            }
        """)
        layout.addWidget(self.totp_setup_field)
        
    def create_totp_verify_content(self, layout):
        """Create TOTP verification content for already setup TOTP."""
        # Instructions
        instructions = QLabel("Enter the 6-digit code from your authenticator app:")
        instructions.setStyleSheet("color: #7f8c8d; margin-bottom: 15px;")
        layout.addWidget(instructions)
        
        # TOTP input field
        self.totp_verify_field = QLineEdit()
        self.totp_verify_field.setPlaceholderText("Enter 6-digit code")
        self.totp_verify_field.setMaxLength(6)
        self.totp_verify_field.setStyleSheet("""
            QLineEdit {
                padding: 12px;
                border: 2px solid #bdc3c7;
                border-radius: 5px;
                font-size: 16px;
                font-family: monospace;
                text-align: center;
                background-color: white;
            }
            QLineEdit:focus {
                border-color: #3498db;
            }
        """)
        layout.addWidget(self.totp_verify_field)
        
        # Time remaining indicator
        self.totp_timer_label = QLabel("Time remaining: 30s")
        self.totp_timer_label.setAlignment(Qt.AlignCenter)
        self.totp_timer_label.setStyleSheet("color: #7f8c8d; font-size: 11px; margin-top: 10px;")
        layout.addWidget(self.totp_timer_label)
        
    def create_action_buttons(self):
        """Create the action buttons."""
        layout = QHBoxLayout()
        layout.setSpacing(10)
        
        # Cancel button
        cancel_button = QPushButton("Cancel")
        cancel_button.setStyleSheet("""
            QPushButton {
                background-color: #95a5a6;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 5px;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #7f8c8d;
            }
        """)
        cancel_button.clicked.connect(self.reject)
        layout.addWidget(cancel_button)
        
        # Verify button
        self.verify_button = QPushButton("Verify")
        self.verify_button.setStyleSheet("""
            QPushButton {
                background-color: #3498db;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 5px;
                font-size: 12px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
            QPushButton:disabled {
                background-color: #bdc3c7;
            }
        """)
        self.verify_button.clicked.connect(self.handle_verification)
        layout.addWidget(self.verify_button)
        
        return layout
        
    def setup_connections(self):
        """Setup signal/slot connections."""
        # Email OTP connections
        if hasattr(self, 'email_otp_field'):
            self.email_otp_field.textChanged.connect(self.validate_email_otp)
            self.email_otp_field.returnPressed.connect(self.handle_verification)
            
        if hasattr(self, 'resend_button'):
            self.resend_button.clicked.connect(self.resend_email_otp)
            
        # TOTP connections
        if hasattr(self, 'totp_setup_field'):
            self.totp_setup_field.textChanged.connect(self.validate_totp)
            self.totp_setup_field.returnPressed.connect(self.handle_verification)
            
        if hasattr(self, 'totp_verify_field'):
            self.totp_verify_field.textChanged.connect(self.validate_totp)
            self.totp_verify_field.returnPressed.connect(self.handle_verification)
            
        # Timers
        self.setup_timers()
        
    def setup_timers(self):
        """Setup various timers for MFA operations."""
        # Email resend countdown timer
        self.resend_timer = QTimer()
        self.resend_timer.timeout.connect(self.update_resend_countdown)
        self.resend_countdown = 0
        
        # TOTP time remaining timer
        self.totp_timer = QTimer()
        self.totp_timer.timeout.connect(self.update_totp_timer)
        
    def initialize_mfa(self):
        """Initialize MFA process based on type."""
        if self.mfa_type in ['email_otp', 'both']:
            self.send_email_otp()
            
        if self.mfa_type in ['totp', 'both']:
            self.start_totp_timer()
            
    def send_email_otp(self):
        """Send email OTP to user."""
        try:
            result = self.auth_controller.send_email_otp(self.username)
            
            if result.get('success'):
                self.email_status_label.setText(f"Verification code sent to {result.get('email', 'your email')}")
                self.email_status_label.setStyleSheet("color: #27ae60;")
                self.start_resend_countdown()
            else:
                self.email_status_label.setText("Failed to send verification code")
                self.email_status_label.setStyleSheet("color: #e74c3c;")
                
        except Exception as e:
            self.email_status_label.setText(f"Error sending code: {str(e)}")
            self.email_status_label.setStyleSheet("color: #e74c3c;")
            
    def resend_email_otp(self):
        """Resend email OTP."""
        self.email_status_label.setText("Sending verification code...")
        self.email_status_label.setStyleSheet("color: #7f8c8d;")
        self.send_email_otp()
        
    def start_resend_countdown(self):
        """Start countdown timer for resend button."""
        self.resend_countdown = 60  # 60 seconds
        self.resend_button.setEnabled(False)
        self.resend_timer.start(1000)  # Update every second
        
    def update_resend_countdown(self):
        """Update resend countdown display."""
        if self.resend_countdown > 0:
            self.countdown_label.setText(f"Resend available in {self.resend_countdown} seconds")
            self.resend_countdown -= 1
        else:
            self.countdown_label.setText("")
            self.resend_button.setEnabled(True)
            self.resend_timer.stop()
            
    def start_totp_timer(self):
        """Start TOTP timer for time remaining display."""
        if hasattr(self, 'totp_timer_label'):
            self.totp_timer.start(1000)  # Update every second
            
    def update_totp_timer(self):
        """Update TOTP time remaining display."""
        import time
        
        # TOTP codes are valid for 30 seconds
        current_time = int(time.time())
        time_remaining = 30 - (current_time % 30)
        
        if hasattr(self, 'totp_timer_label'):
            self.totp_timer_label.setText(f"Time remaining: {time_remaining}s")
            
            # Change color when time is running out
            if time_remaining <= 10:
                self.totp_timer_label.setStyleSheet("color: #e74c3c; font-size: 11px; margin-top: 10px;")
            else:
                self.totp_timer_label.setStyleSheet("color: #7f8c8d; font-size: 11px; margin-top: 10px;")
                
    def validate_email_otp(self):
        """Validate email OTP input."""
        if hasattr(self, 'email_otp_field'):
            code = self.email_otp_field.text().strip()
            self.verify_button.setEnabled(len(code) == 6 and code.isdigit())
            
    def validate_totp(self):
        """Validate TOTP input."""
        code = ""
        
        if hasattr(self, 'totp_setup_field'):
            code = self.totp_setup_field.text().strip()
        elif hasattr(self, 'totp_verify_field'):
            code = self.totp_verify_field.text().strip()
            
        self.verify_button.setEnabled(len(code) == 6 and code.isdigit())
        
    def handle_verification(self):
        """Handle MFA verification process."""
        if not self.verify_button.isEnabled():
            return
            
        # Determine which verification method to use
        if self.mfa_type == 'both':
            # Check which tab is active
            if hasattr(self, 'tab_widget'):
                current_tab = self.tab_widget.currentIndex()
                if current_tab == 0:  # Email tab
                    self.verify_email_otp()
                else:  # TOTP tab
                    self.verify_totp()
        elif self.mfa_type == 'email_otp':
            self.verify_email_otp()
        elif self.mfa_type == 'totp':
            self.verify_totp()
            
    def verify_email_otp(self):
        """Verify email OTP code."""
        if not hasattr(self, 'email_otp_field'):
            return
            
        code = self.email_otp_field.text().strip()
        
        if not code or len(code) != 6:
            MessageBoxes.warning(self, "Invalid Code", "Please enter a 6-digit verification code.")
            return
            
        try:
            result = self.auth_controller.verify_email_otp(self.username, code)
            
            if result.get('success'):
                self.verification_successful = True
                self.mfa_completed.emit('email_otp')
                MessageBoxes.info(self, "Verification Successful", "Email verification completed successfully.")
                self.accept()
            else:
                error_msg = result.get('message', 'Invalid verification code')
                MessageBoxes.show_error(self, "Verification Failed", error_msg)
                self.email_otp_field.clear()
                self.email_otp_field.setFocus()
                
        except Exception as e:
            MessageBoxes.show_error(self, "Verification Error", 
                             f"An error occurred during verification: {str(e)}")
            
    def verify_totp(self):
        """Verify TOTP code."""
        code = ""
        
        if hasattr(self, 'totp_setup_field'):
            code = self.totp_setup_field.text().strip()
            is_setup = True
        elif hasattr(self, 'totp_verify_field'):
            code = self.totp_verify_field.text().strip()
            is_setup = False
        else:
            return
            
        if not code or len(code) != 6:
            MessageBoxes.warning(self, "Invalid Code", "Please enter a 6-digit verification code.")
            return
            
        try:
            if is_setup:
                # Setup verification
                result = self.auth_controller.setup_totp(self.username, code)
            else:
                # Normal verification
                result = self.auth_controller.verify_totp(self.username, code)
                
            if result.get('success'):
                self.verification_successful = True
                self.mfa_completed.emit('totp')
                
                if is_setup:
                    MessageBoxes.info(self, "Setup Successful", 
                                    "TOTP has been set up successfully!")
                else:
                    MessageBoxes.info(self, "Verification Successful", 
                                    "TOTP verification completed successfully.")
                    
                self.accept()
            else:
                error_msg = result.get('message', 'Invalid verification code')
                MessageBoxes.show_error(self, "Verification Failed", error_msg)
                
                # Clear the appropriate field
                if is_setup:
                    self.totp_setup_field.clear()
                    self.totp_setup_field.setFocus()
                else:
                    self.totp_verify_field.clear()
                    self.totp_verify_field.setFocus()
                    
        except Exception as e:
            MessageBoxes.show_error(self, "Verification Error", 
                             f"An error occurred during verification: {str(e)}")
            
    def closeEvent(self, event):
        """Handle dialog close event."""
        # Stop timers
        if hasattr(self, 'resend_timer'):
            self.resend_timer.stop()
        if hasattr(self, 'totp_timer'):
            self.totp_timer.stop()
            
        super().closeEvent(event) 
