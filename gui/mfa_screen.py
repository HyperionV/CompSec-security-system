from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QLineEdit, QPushButton, QGroupBox, QFormLayout)
from PyQt5.QtCore import pyqtSignal, Qt, QTimer
from PyQt5.QtGui import QFont
from .utils.dialogs import show_error, show_info

class MFAScreen(QWidget):
    mfa_successful = pyqtSignal()
    back_to_login = pyqtSignal()
    
    def __init__(self, auth_manager, mfa_manager, user_info, parent=None):
        super().__init__(parent)
        self.auth_manager = auth_manager
        self.mfa_manager = mfa_manager
        self.user_info = user_info
        self.otp_sent = False
        self.countdown_timer = QTimer()
        self.countdown_timer.timeout.connect(self.update_countdown)
        self.remaining_time = 0
        self.setup_ui()
        self.send_otp()
    
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
        
        # OTP form
        form_group = QGroupBox("Enter Verification Code")
        form_layout = QFormLayout()
        
        # Status label
        self.status_label = QLabel("Sending OTP code to your email...")
        self.status_label.setWordWrap(True)
        self.status_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.status_label)
        
        # OTP input
        self.otp_input = QLineEdit()
        self.otp_input.setPlaceholderText("Enter 6-digit code")
        self.otp_input.setMaxLength(6)
        self.otp_input.setAlignment(Qt.AlignCenter)
        self.otp_input.returnPressed.connect(self.verify_otp)
        font = QFont("Courier", 14)
        self.otp_input.setFont(font)
        form_layout.addRow("OTP Code:", self.otp_input)
        
        form_group.setLayout(form_layout)
        layout.addWidget(form_group)
        
        # Countdown label
        self.countdown_label = QLabel("")
        self.countdown_label.setAlignment(Qt.AlignCenter)
        self.countdown_label.setStyleSheet("color: #666; font-style: italic;")
        layout.addWidget(self.countdown_label)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        self.verify_button = QPushButton("Verify Code")
        self.verify_button.clicked.connect(self.verify_otp)
        button_layout.addWidget(self.verify_button)
        
        self.resend_button = QPushButton("Resend Code")
        self.resend_button.clicked.connect(self.send_otp)
        button_layout.addWidget(self.resend_button)
        
        self.back_button = QPushButton("Back to Login")
        self.back_button.clicked.connect(self.back_to_login.emit)
        button_layout.addWidget(self.back_button)
        
        layout.addLayout(button_layout)
        layout.addStretch()
        
        self.setLayout(layout)
    
    def send_otp(self):
        """Send OTP code to user"""
        try:
            success, message, otp_data = self.mfa_manager.generate_otp(self.user_info['id'])
            
            if success:
                self.otp_sent = True
                self.status_label.setText(
                    f"OTP code sent to {self.user_info['email']}\n"
                    f"For testing purposes, your OTP code is: {otp_data['otp_code']}\n"
                    "Code expires in 5 minutes."
                )
                self.status_label.setStyleSheet("color: green;")
                
                # Start countdown timer
                self.remaining_time = 300  # 5 minutes
                self.countdown_timer.start(1000)  # Update every second
                self.update_countdown()
                
                # Enable input and verify button
                self.otp_input.setEnabled(True)
                self.verify_button.setEnabled(True)
                self.otp_input.setFocus()
                
            else:
                self.status_label.setText(f"Failed to send OTP: {message}")
                self.status_label.setStyleSheet("color: red;")
                
        except Exception as e:
            self.status_label.setText(f"Error sending OTP: {str(e)}")
            self.status_label.setStyleSheet("color: red;")
    
    def verify_otp(self):
        """Verify the entered OTP code"""
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
                # Complete the login process - skip MFA verification since we already verified it
                login_success, login_message = self.auth_manager.complete_login_with_mfa(
                    self.user_info, otp_code, skip_mfa_verification=True
                )
                
                if login_success:
                    self.countdown_timer.stop()
                    self.mfa_successful.emit()
                else:
                    show_error(self, "Login Error", login_message)
            else:
                show_error(self, "Verification Failed", message)
                self.otp_input.clear()
                
        except Exception as e:
            show_error(self, "Verification Error", f"Error verifying OTP: {str(e)}")
    
    def update_countdown(self):
        """Update the countdown display"""
        if self.remaining_time > 0:
            minutes = self.remaining_time // 60
            seconds = self.remaining_time % 60
            self.countdown_label.setText(f"Code expires in {minutes:02d}:{seconds:02d}")
            self.remaining_time -= 1
        else:
            self.countdown_timer.stop()
            self.countdown_label.setText("OTP code has expired. Please request a new code.")
            self.countdown_label.setStyleSheet("color: red; font-style: italic;")
            self.otp_input.setEnabled(False)
            self.verify_button.setEnabled(False)
    
    def reset_for_new_user(self, user_info):
        """Reset the screen for a new user"""
        self.user_info = user_info
        self.otp_sent = False
        self.countdown_timer.stop()
        self.otp_input.clear()
        self.otp_input.setEnabled(False)
        self.verify_button.setEnabled(False)
        self.status_label.setText("Sending OTP code to your email...")
        self.status_label.setStyleSheet("")
        self.countdown_label.setText("")
        self.countdown_label.setStyleSheet("color: #666; font-style: italic;")
        
        # Update user label
        user_label = self.findChild(QLabel)
        for child in self.findChildren(QLabel):
            if "Logged in as:" in child.text():
                child.setText(f"Logged in as: {user_info['email']}")
                break 