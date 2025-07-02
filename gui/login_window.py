from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLineEdit, 
                             QPushButton, QLabel, QMessageBox)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont
from gui.registration_window import RegistrationWindow
from gui.main_window import MainWindow
from modules.auth import auth_manager, request_otp_for_user, verify_otp_for_user, verify_totp_for_user
from modules.database import db_manager
from modules.session import session_manager
from .otp_dialog import show_otp_dialog

class LoginWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.registration_window = None
        self.main_window = None
        self.init_ui()
        
    def init_ui(self):
        self.setWindowTitle("SecurityApp - Login")
        self.setFixedSize(350, 250)
        
        layout = QVBoxLayout()
        
        title = QLabel("SecurityApp")
        title.setAlignment(Qt.AlignCenter)
        title.setFont(QFont("Arial", 18, QFont.Bold))
        title.setStyleSheet("color: #2c3e50; margin: 20px;")
        layout.addWidget(title)
        
        # Email field
        self.email_input = QLineEdit()
        self.email_input.setPlaceholderText("Email")
        self.email_input.setStyleSheet("padding: 8px; font-size: 14px; border: 1px solid #ddd; border-radius: 4px;")
        layout.addWidget(self.email_input)
        
        # Password field
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Password")
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setStyleSheet("padding: 8px; font-size: 14px; border: 1px solid #ddd; border-radius: 4px;")
        layout.addWidget(self.password_input)
        
        # Login button
        login_button = QPushButton("Login")
        login_button.setStyleSheet("""
            QPushButton {
                background-color: #3498db;
                color: white;
                border: none;
                padding: 10px;
                font-size: 14px;
                border-radius: 5px;
                margin: 10px 0;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
        """)
        login_button.clicked.connect(self.handle_login)
        layout.addWidget(login_button)
        
        # Register button
        register_button = QPushButton("Create New Account")
        register_button.setStyleSheet("""
            QPushButton {
                background-color: #27ae60;
                color: white;
                border: none;
                padding: 10px;
                font-size: 14px;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #229954;
            }
        """)
        register_button.clicked.connect(self.open_registration)
        layout.addWidget(register_button)
        
        self.setLayout(layout)
    
    def handle_login(self):
        email = self.email_input.text().strip()
        password = self.password_input.text()
        
        if not email or not password:
            QMessageBox.warning(self, "Input Error", "Please enter both email and password.")
            return
        
        # First verify email and password
        success, message, user_data = auth_manager.login_user(email, password)
        
        if success:
            # Check if user has TOTP setup
            totp_secret = db_manager.get_user_totp_secret(user_data['id'])
            
            if totp_secret:
                # User has TOTP - offer choice between OTP and TOTP
                choice = self.show_mfa_choice_dialog()
                
                if choice == "totp":
                    # TOTP authentication
                    totp_code = show_otp_dialog(user_data['email'], self, "TOTP", "Enter the 6-digit code from your authenticator app:")
                    
                    if totp_code:
                        if verify_totp_for_user(user_data['id'], totp_code):
                            self.complete_login(user_data)
                        else:
                            QMessageBox.critical(self, "TOTP Verification Failed", "Invalid TOTP code. Please check your authenticator app and try again.")
                            self.password_input.clear()
                    else:
                        QMessageBox.information(self, "Login Cancelled", "TOTP verification was cancelled.")
                        self.password_input.clear()
                        
                elif choice == "otp":
                    # Traditional OTP authentication
                    self.handle_otp_authentication(user_data)
                else:
                    # User cancelled choice
                    self.password_input.clear()
            else:
                # User doesn't have TOTP - use traditional OTP
                self.handle_otp_authentication(user_data)
        else:
            QMessageBox.critical(self, "Login Failed", message)
            self.password_input.clear()
    
    def show_mfa_choice_dialog(self):
        """Show dialog to choose between OTP and TOTP verification"""
        msg = QMessageBox(self)
        msg.setWindowTitle("Choose Verification Method")
        msg.setText("You have multiple verification methods available.")
        msg.setInformativeText("How would you like to verify your identity?")
        
        totp_button = msg.addButton("📱 Authenticator App (TOTP)", QMessageBox.ActionRole)
        otp_button = msg.addButton("📧 Email Code (OTP)", QMessageBox.ActionRole)
        cancel_button = msg.addButton(QMessageBox.Cancel)
        
        msg.exec_()
        
        if msg.clickedButton() == totp_button:
            return "totp"
        elif msg.clickedButton() == otp_button:
            return "otp"
        else:
            return None
    
    def handle_otp_authentication(self, user_data):
        """Handle traditional OTP authentication flow"""
        if request_otp_for_user(user_data['id']):
            otp_code = show_otp_dialog(user_data['email'], self)
            
            if otp_code:
                if verify_otp_for_user(user_data['id'], otp_code):
                    self.complete_login(user_data)
                else:
                    QMessageBox.critical(self, "OTP Verification Failed", "Invalid or expired OTP code. Please try again.")
                    self.password_input.clear()
            else:
                QMessageBox.information(self, "Login Cancelled", "OTP verification was cancelled.")
                self.password_input.clear()
        else:
            QMessageBox.critical(self, "System Error", "Failed to send OTP. Please try again later.")
            self.password_input.clear()
    
    def complete_login(self, user_data):
        """Complete the login process after successful verification"""
        session_manager.login(user_data)
        QMessageBox.information(self, "Login Successful", f"Welcome back, {user_data['name']}!")
        
        from .main_window import MainWindow
        self.main_window = MainWindow()
        self.main_window.show()
        self.close()
    
    def open_registration(self):
        if not self.registration_window:
            self.registration_window = RegistrationWindow()
        self.registration_window.show()
        self.registration_window.raise_()
        self.registration_window.activateWindow() 