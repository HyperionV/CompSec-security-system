from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QLineEdit, QPushButton, QGroupBox, QFormLayout,
                             QTextEdit, QFrame)
from PyQt5.QtCore import pyqtSignal, Qt, QTimer
from PyQt5.QtGui import QFont, QPixmap
from .utils.dialogs import show_error, show_info
import base64

class MFAScreen(QWidget):
    mfa_successful = pyqtSignal()
    back_to_login = pyqtSignal()
    
    def __init__(self, auth_manager, mfa_manager, user_info, parent=None):
        super().__init__(parent)
        self.auth_manager = auth_manager
        self.mfa_manager = mfa_manager
        self.user_info = user_info
        self.otp_sent = False
        self.totp_setup = False
        self.countdown_timer = QTimer()
        self.countdown_timer.timeout.connect(self.update_countdown)
        self.remaining_time = 0
        self.setup_ui()
        self.initialize_mfa_options()
    
    def setup_ui(self):
        layout = QVBoxLayout()
        
        # Title
        title_label = QLabel("Multi-Factor Authentication")
        title_label.setAlignment(Qt.AlignCenter)
        title_font = QFont("Arial", 16, QFont.Bold)
        title_label.setFont(title_font)
        layout.addWidget(title_label)
        
        # User info
        user_label = QLabel(f"Logged in as: {self.user_info['email']}")
        user_label.setAlignment(Qt.AlignCenter)
        user_label.setStyleSheet("color: #666;")
        layout.addWidget(user_label)
        
        # Main horizontal layout for split screen
        main_layout = QHBoxLayout()
        
        # Left side - OTP (Email)
        self.setup_otp_section(main_layout)
        
        # Vertical separator
        separator = QFrame()
        separator.setFrameShape(QFrame.VLine)
        separator.setFrameShadow(QFrame.Sunken)
        separator.setStyleSheet("color: #ccc;")
        main_layout.addWidget(separator)
        
        # Right side - TOTP (Google Authenticator)
        self.setup_totp_section(main_layout)
        
        layout.addLayout(main_layout)
        
        # Bottom buttons
        button_layout = QHBoxLayout()
        
        self.back_button = QPushButton("Back to Login")
        self.back_button.clicked.connect(self.back_to_login.emit)
        button_layout.addStretch()
        button_layout.addWidget(self.back_button)
        
        layout.addLayout(button_layout)
        self.setLayout(layout)
    
    def setup_otp_section(self, parent_layout):
        """Setup the OTP (email) section on the left"""
        otp_layout = QVBoxLayout()
        
        # OTP Group
        otp_group = QGroupBox("Email OTP Verification")
        otp_group_layout = QVBoxLayout()
        
        # Status label
        self.otp_status_label = QLabel("Click 'Send OTP' to receive verification code")
        self.otp_status_label.setWordWrap(True)
        self.otp_status_label.setAlignment(Qt.AlignCenter)
        otp_group_layout.addWidget(self.otp_status_label)
        
        # OTP input
        form_layout = QFormLayout()
        self.otp_input = QLineEdit()
        self.otp_input.setPlaceholderText("Enter 6-digit code")
        self.otp_input.setMaxLength(6)
        self.otp_input.setAlignment(Qt.AlignCenter)
        self.otp_input.returnPressed.connect(self.verify_otp)
        font = QFont("Courier", 14)
        self.otp_input.setFont(font)
        form_layout.addRow("OTP Code:", self.otp_input)
        otp_group_layout.addLayout(form_layout)
        
        # Countdown label
        self.countdown_label = QLabel("")
        self.countdown_label.setAlignment(Qt.AlignCenter)
        self.countdown_label.setStyleSheet("color: #666; font-style: italic;")
        otp_group_layout.addWidget(self.countdown_label)
        
        # OTP Buttons
        otp_button_layout = QHBoxLayout()
        self.send_otp_button = QPushButton("Send OTP")
        self.send_otp_button.clicked.connect(self.send_otp)
        self.verify_otp_button = QPushButton("Verify OTP")
        self.verify_otp_button.clicked.connect(self.verify_otp)
        self.verify_otp_button.setEnabled(False)
        
        otp_button_layout.addWidget(self.send_otp_button)
        otp_button_layout.addWidget(self.verify_otp_button)
        otp_group_layout.addLayout(otp_button_layout)
        
        otp_group.setLayout(otp_group_layout)
        otp_layout.addWidget(otp_group)
        otp_layout.addStretch()
        
        parent_layout.addLayout(otp_layout)
    
    def setup_totp_section(self, parent_layout):
        """Setup the TOTP (Google Authenticator) section on the right"""
        totp_layout = QVBoxLayout()
        
        # TOTP Group
        totp_group = QGroupBox("TOTP (Google Authenticator)")
        totp_group_layout = QVBoxLayout()
        
        # TOTP Status
        self.totp_status_label = QLabel("Setting up TOTP...")
        self.totp_status_label.setWordWrap(True)
        self.totp_status_label.setAlignment(Qt.AlignCenter)
        totp_group_layout.addWidget(self.totp_status_label)
        
        # QR Code display
        self.qr_label = QLabel()
        self.qr_label.setAlignment(Qt.AlignCenter)
        self.qr_label.setMinimumSize(200, 200)
        self.qr_label.setStyleSheet("border: 1px solid #ccc;")
        totp_group_layout.addWidget(self.qr_label)
        
        # Manual entry info
        self.manual_key_label = QLabel()
        self.manual_key_label.setWordWrap(True)
        self.manual_key_label.setStyleSheet("font-size: 10px; color: #666;")
        self.manual_key_label.setAlignment(Qt.AlignCenter)
        totp_group_layout.addWidget(self.manual_key_label)
        
        # TOTP input
        totp_form_layout = QFormLayout()
        self.totp_input = QLineEdit()
        self.totp_input.setPlaceholderText("Enter 6-digit TOTP")
        self.totp_input.setMaxLength(6)
        self.totp_input.setAlignment(Qt.AlignCenter)
        self.totp_input.returnPressed.connect(self.verify_totp)
        totp_font = QFont("Courier", 14)
        self.totp_input.setFont(totp_font)
        totp_form_layout.addRow("TOTP Code:", self.totp_input)
        totp_group_layout.addLayout(totp_form_layout)
        
        # TOTP Buttons
        totp_button_layout = QHBoxLayout()
        self.setup_totp_button = QPushButton("Setup TOTP")
        self.setup_totp_button.clicked.connect(self.setup_totp)
        self.verify_totp_button = QPushButton("Verify TOTP")
        self.verify_totp_button.clicked.connect(self.verify_totp)
        self.verify_totp_button.setEnabled(False)
        
        totp_button_layout.addWidget(self.setup_totp_button)
        totp_button_layout.addWidget(self.verify_totp_button)
        totp_group_layout.addLayout(totp_button_layout)
        
        totp_group.setLayout(totp_group_layout)
        totp_layout.addWidget(totp_group)
        totp_layout.addStretch()
        
        parent_layout.addLayout(totp_layout)
    
    def initialize_mfa_options(self):
        """Initialize both MFA options"""
        # Check if user has TOTP setup
        has_totp = self.mfa_manager.has_totp_setup(self.user_info['id'])
        
        if has_totp:
            # User has TOTP, show existing QR and enable verification
            self.load_existing_totp()
        else:
            # User doesn't have TOTP, show setup option
            self.totp_status_label.setText("TOTP not set up. Click 'Setup TOTP' to configure Google Authenticator.")
            self.setup_totp_button.setText("Setup TOTP")
    
    def load_existing_totp(self):
        """Load existing TOTP QR code"""
        success, result = self.mfa_manager.get_user_totp_qr(self.user_info['id'], self.user_info['email'])
        
        if success:
            self.display_qr_code(result['qr_code_base64'])
            self.manual_key_label.setText(f"Manual entry key: {result['secret']}")
            self.totp_status_label.setText("TOTP is set up. Enter code from Google Authenticator.")
            self.setup_totp_button.setText("Show QR Code")
            self.verify_totp_button.setEnabled(True)
            self.totp_setup = True
    
    def setup_totp(self):
        """Setup or show TOTP QR code"""
        if self.totp_setup:
            # Already setup, just show QR code
            self.load_existing_totp()
        else:
            # Setup new TOTP
            success, result = self.mfa_manager.setup_user_totp(self.user_info['id'], self.user_info['email'])
            
            if success:
                self.display_qr_code(result['qr_code_base64'])
                self.manual_key_label.setText(f"Manual entry key: {result['secret']}")
                self.totp_status_label.setText("Scan QR code with Google Authenticator, then enter the 6-digit code.")
                self.setup_totp_button.setText("Show QR Code")
                self.verify_totp_button.setEnabled(True)
                self.totp_setup = True
            else:
                show_error(self, "TOTP Setup Failed", result)
    
    def display_qr_code(self, base64_data):
        """Display QR code from base64 data"""
        try:
            qr_data = base64.b64decode(base64_data)
            pixmap = QPixmap()
            pixmap.loadFromData(qr_data)
            scaled_pixmap = pixmap.scaled(180, 180, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            self.qr_label.setPixmap(scaled_pixmap)
        except Exception as e:
            self.qr_label.setText(f"QR Code Error: {str(e)}")
    
    def send_otp(self):
        """Send OTP code to user email"""
        try:
            success, message, otp_data = self.mfa_manager.generate_otp(self.user_info['id'])
            
            if success:
                self.otp_sent = True
                self.otp_status_label.setText(
                    f"OTP sent to {self.user_info['email']}\n"
                    f"For testing: {otp_data['otp_code']}\n"
                    "Code expires in 5 minutes."
                )
                self.otp_status_label.setStyleSheet("color: green;")
                
                # Start countdown
                self.remaining_time = 300
                self.countdown_timer.start(1000)
                self.update_countdown()
                
                # Enable verification
                self.otp_input.setEnabled(True)
                self.verify_otp_button.setEnabled(True)
                self.otp_input.setFocus()
                
            else:
                self.otp_status_label.setText(f"Failed to send OTP: {message}")
                self.otp_status_label.setStyleSheet("color: red;")
                
        except Exception as e:
            self.otp_status_label.setText(f"Error sending OTP: {str(e)}")
            self.otp_status_label.setStyleSheet("color: red;")
    
    def verify_otp(self):
        """Verify OTP code"""
        otp_code = self.otp_input.text().strip()
        
        if not otp_code:
            show_error(self, "Verification Error", "Please enter the OTP code.")
            return
        
        if len(otp_code) != 6:
            show_error(self, "Verification Error", "OTP code must be 6 digits.")
            return
        
        try:
            success, message = self.mfa_manager.verify_otp(self.user_info['id'], otp_code)
            
            if success:
                # Complete login with OTP
                login_success, login_message = self.auth_manager.complete_login_with_mfa(
                    self.user_info, otp_code, "otp", skip_mfa_verification=True
                )
                
                if login_success:
                    self.cleanup_timer()
                    self.mfa_successful.emit()
                else:
                    show_error(self, "Login Error", login_message)
            else:
                show_error(self, "Verification Failed", message)
                self.otp_input.clear()
                
        except Exception as e:
            show_error(self, "Verification Error", f"Error verifying OTP: {str(e)}")
    
    def verify_totp(self):
        """Verify TOTP code"""
        totp_code = self.totp_input.text().strip()
        
        if not totp_code:
            show_error(self, "Verification Error", "Please enter the TOTP code.")
            return
        
        if len(totp_code) != 6:
            show_error(self, "Verification Error", "TOTP code must be 6 digits.")
            return
        
        try:
            success, message = self.mfa_manager.verify_user_totp(self.user_info['id'], totp_code)
            
            if success:
                # Complete login with TOTP
                login_success, login_message = self.auth_manager.complete_login_with_mfa(
                    self.user_info, totp_code, "totp", skip_mfa_verification=True
                )
                
                if login_success:
                    self.cleanup_timer()
                    self.mfa_successful.emit()
                else:
                    show_error(self, "Login Error", login_message)
            else:
                show_error(self, "Verification Failed", message)
                self.totp_input.clear()
                
        except Exception as e:
            show_error(self, "Verification Error", f"Error verifying TOTP: {str(e)}")
    
    def update_countdown(self):
        """Update OTP countdown display"""
        if self.remaining_time > 0:
            minutes = self.remaining_time // 60
            seconds = self.remaining_time % 60
            self.countdown_label.setText(f"OTP expires in {minutes:02d}:{seconds:02d}")
            self.remaining_time -= 1
        else:
            self.countdown_timer.stop()
            self.countdown_label.setText("OTP code has expired. Please request a new code.")
            self.countdown_label.setStyleSheet("color: red; font-style: italic;")
            self.otp_input.setEnabled(False)
            self.verify_otp_button.setEnabled(False)
    
    def reset_for_new_user(self, user_info):
        """Reset the screen for a new user"""
        self.cleanup_timer()
        self.user_info = user_info
        self.otp_sent = False
        self.totp_setup = False
        
        # Reset OTP section
        self.otp_input.clear()
        self.otp_input.setEnabled(False)
        self.verify_otp_button.setEnabled(False)
        self.otp_status_label.setText("Click 'Send OTP' to receive verification code")
        self.otp_status_label.setStyleSheet("")
        self.countdown_label.setText("")
        self.countdown_label.setStyleSheet("color: #666; font-style: italic;")
        
        # Reset TOTP section
        self.totp_input.clear()
        self.verify_totp_button.setEnabled(False)
        self.qr_label.clear()
        self.manual_key_label.clear()
        
        # Update user label
        for child in self.findChildren(QLabel):
            if "Logged in as:" in child.text():
                child.setText(f"Logged in as: {user_info['email']}")
                break
        
        # Reinitialize MFA options for new user
        self.initialize_mfa_options()
    
    def cleanup_timer(self):
        """Clean up the countdown timer"""
        if self.countdown_timer:
            self.countdown_timer.stop()
            self.remaining_time = 0
    
    def cleanup(self):
        """Clean up resources when screen is destroyed"""
        self.cleanup_timer()
        self.otp_sent = False
        self.totp_setup = False
        self.otp_input.clear()
        self.totp_input.clear()
    
    def closeEvent(self, event):
        """Handle widget close event"""
        self.cleanup()
        super().closeEvent(event)
    
    def __del__(self):
        """Destructor to ensure cleanup"""
        try:
            self.cleanup()
        except:
            pass 