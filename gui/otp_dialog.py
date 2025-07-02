import sys
from PyQt5.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel, 
                            QLineEdit, QPushButton, QMessageBox, QFrame)
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QFont, QIntValidator

class OTPDialog(QDialog):
    def __init__(self, user_email, parent=None, dialog_type="OTP", custom_instruction=None):
        super().__init__(parent)
        self.user_email = user_email
        self.dialog_type = dialog_type
        self.custom_instruction = custom_instruction
        self.otp_code = None
        self.setup_ui()
        
    def setup_ui(self):
        # Set window title based on dialog type
        window_title = "TOTP Verification" if self.dialog_type == "TOTP" else "OTP Verification"
        self.setWindowTitle(window_title)
        self.setFixedSize(400, 300)
        self.setModal(True)
        
        # Main layout
        layout = QVBoxLayout()
        layout.setSpacing(20)
        layout.setContentsMargins(30, 30, 30, 30)
        
        # Title with appropriate icon
        title_icon = "📱" if self.dialog_type == "TOTP" else "🔐"
        title_text = f"{title_icon} Two-Factor Authentication"
        title_label = QLabel(title_text)
        title_font = QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(title_label)
        
        # Separator
        separator = QFrame()
        separator.setFrameShape(QFrame.HLine)
        separator.setFrameShadow(QFrame.Sunken)
        layout.addWidget(separator)
        
        # Instructions - customizable for TOTP
        if self.custom_instruction:
            instruction_text = self.custom_instruction
        else:
            instruction_text = f"Please enter the 6-digit code sent to:\n{self.user_email}"
            
        instruction_label = QLabel(instruction_text)
        instruction_label.setAlignment(Qt.AlignCenter)
        instruction_label.setWordWrap(True)
        layout.addWidget(instruction_label)
        
        # OTP Input
        otp_layout = QHBoxLayout()
        otp_layout.setAlignment(Qt.AlignCenter)
        
        otp_label = QLabel("Security Code:")
        otp_label.setFont(QFont("Arial", 10, QFont.Bold))
        otp_layout.addWidget(otp_label)
        
        self.otp_input = QLineEdit()
        self.otp_input.setMaxLength(6)
        self.otp_input.setValidator(QIntValidator(0, 999999))
        self.otp_input.setPlaceholderText("000000")
        self.otp_input.setAlignment(Qt.AlignCenter)
        self.otp_input.setFont(QFont("Courier", 14, QFont.Bold))
        self.otp_input.setStyleSheet("""
            QLineEdit {
                padding: 10px;
                border: 2px solid #ccc;
                border-radius: 5px;
                background-color: #f9f9f9;
            }
            QLineEdit:focus {
                border-color: #4CAF50;
                background-color: white;
            }
        """)
        self.otp_input.textChanged.connect(self.validate_input)
        otp_layout.addWidget(self.otp_input)
        
        layout.addLayout(otp_layout)
        
        # Status label
        self.status_label = QLabel("")
        self.status_label.setAlignment(Qt.AlignCenter)
        self.status_label.setStyleSheet("color: #888; font-size: 12px;")
        layout.addWidget(self.status_label)
        
        # Buttons
        button_layout = QHBoxLayout()
        button_layout.setAlignment(Qt.AlignCenter)
        
        self.verify_button = QPushButton("Verify Code")
        self.verify_button.setEnabled(False)
        self.verify_button.clicked.connect(self.verify_otp)
        self.verify_button.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 5px;
                font-weight: bold;
                min-width: 100px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QPushButton:disabled {
                background-color: #cccccc;
                color: #666666;
            }
        """)
        button_layout.addWidget(self.verify_button)
        
        cancel_button = QPushButton("Cancel")
        cancel_button.clicked.connect(self.reject)
        cancel_button.setStyleSheet("""
            QPushButton {
                background-color: #f44336;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 5px;
                font-weight: bold;
                min-width: 100px;
            }
            QPushButton:hover {
                background-color: #da190b;
            }
        """)
        button_layout.addWidget(cancel_button)
        
        layout.addLayout(button_layout)
        
        # Timer info - different for TOTP vs OTP
        if self.dialog_type == "TOTP":
            timer_text = "⏰ Code changes every 30 seconds"
        else:
            timer_text = "⏰ Code expires in 5 minutes"
            
        timer_label = QLabel(timer_text)
        timer_label.setAlignment(Qt.AlignCenter)
        timer_label.setStyleSheet("color: #FF9800; font-size: 11px; font-style: italic;")
        layout.addWidget(timer_label)
        
        self.setLayout(layout)
        
        # Focus on input
        self.otp_input.setFocus()
        
    def validate_input(self, text):
        """Real-time input validation"""
        if len(text) == 6 and text.isdigit():
            self.verify_button.setEnabled(True)
            self.status_label.setText("✅ Ready to verify")
            self.status_label.setStyleSheet("color: green; font-size: 12px;")
        else:
            self.verify_button.setEnabled(False)
            if len(text) == 0:
                self.status_label.setText("")
            elif not text.isdigit():
                self.status_label.setText("❌ Only numbers allowed")
                self.status_label.setStyleSheet("color: red; font-size: 12px;")
            else:
                remaining = 6 - len(text)
                self.status_label.setText(f"📝 Enter {remaining} more digit{'s' if remaining > 1 else ''}")
                self.status_label.setStyleSheet("color: #888; font-size: 12px;")
    
    def verify_otp(self):
        """Handle OTP verification"""
        self.otp_code = self.otp_input.text()
        if len(self.otp_code) == 6 and self.otp_code.isdigit():
            self.accept()
        else:
            QMessageBox.warning(self, "Invalid Code", "Please enter a valid 6-digit code.")
    
    def get_otp_code(self):
        """Return the entered OTP code"""
        return self.otp_code

def show_otp_dialog(user_email, parent=None, dialog_type="OTP", custom_instruction=None):
    """Show OTP/TOTP dialog and return the entered code or None if cancelled"""
    dialog = OTPDialog(user_email, parent, dialog_type, custom_instruction)
    if dialog.exec_() == QDialog.Accepted:
        return dialog.get_otp_code()
    return None 