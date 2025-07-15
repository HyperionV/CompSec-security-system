from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTabWidget, 
                             QLabel, QLineEdit, QPushButton, QFormLayout,
                             QGroupBox, QTextEdit, QInputDialog)
from PyQt5.QtCore import pyqtSignal, Qt
from PyQt5.QtGui import QFont
from .utils.dialogs import show_error, show_info, show_warning, RegistrationSuccessDialog

class LoginScreen(QWidget):
    login_successful = pyqtSignal(dict)
    
    def __init__(self, auth_manager, parent=None):
        super().__init__(parent)
        self.auth_manager = auth_manager
        self.setup_ui()
    
    def setup_ui(self):
        layout = QVBoxLayout()
        
        # Title
        title_label = QLabel("Security Application")
        title_label.setAlignment(Qt.AlignCenter)
        title_font = QFont("Arial", 18, QFont.Bold)
        title_label.setFont(title_font)
        layout.addWidget(title_label)
        
        # Tab widget
        self.tab_widget = QTabWidget()
        self.tab_widget.addTab(self.create_login_tab(), "Login")
        self.tab_widget.addTab(self.create_register_tab(), "Register")
        self.tab_widget.addTab(self.create_recovery_tab(), "Account Recovery")
        
        layout.addWidget(self.tab_widget)
        layout.addStretch()
        
        self.setLayout(layout)
    
    def create_login_tab(self):
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Login form
        form_group = QGroupBox("Login to Your Account")
        form_layout = QFormLayout()
        
        self.login_email = QLineEdit()
        self.login_email.setPlaceholderText("Enter your email address")
        form_layout.addRow("Email:", self.login_email)
        
        self.login_password = QLineEdit()
        self.login_password.setEchoMode(QLineEdit.Password)
        self.login_password.setPlaceholderText("Enter your passphrase")
        self.login_password.returnPressed.connect(self.handle_login)
        form_layout.addRow("Passphrase:", self.login_password)
        
        form_group.setLayout(form_layout)
        layout.addWidget(form_group)
        
        # Login button
        self.login_button = QPushButton("Login")
        self.login_button.clicked.connect(self.handle_login)
        layout.addWidget(self.login_button)
        
        layout.addStretch()
        widget.setLayout(layout)
        return widget
    
    def create_register_tab(self):
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Registration form
        form_group = QGroupBox("Create New Account")
        form_layout = QFormLayout()
        
        self.reg_email = QLineEdit()
        self.reg_email.setPlaceholderText("Enter your email address")
        form_layout.addRow("Email:", self.reg_email)
        
        self.reg_name = QLineEdit()
        self.reg_name.setPlaceholderText("Enter your full name")
        form_layout.addRow("Full Name:", self.reg_name)
        
        self.reg_phone = QLineEdit()
        self.reg_phone.setPlaceholderText("Optional - Phone number")
        form_layout.addRow("Phone:", self.reg_phone)
        
        self.reg_address = QLineEdit()
        self.reg_address.setPlaceholderText("Optional - Address")
        form_layout.addRow("Address:", self.reg_address)
        
        self.reg_birth_date = QLineEdit()
        self.reg_birth_date.setPlaceholderText("Optional - YYYY-MM-DD")
        form_layout.addRow("Birth Date:", self.reg_birth_date)
        
        self.reg_password = QLineEdit()
        self.reg_password.setEchoMode(QLineEdit.Password)
        self.reg_password.setPlaceholderText("Enter a strong passphrase")
        form_layout.addRow("Passphrase:", self.reg_password)
        
        self.reg_confirm_password = QLineEdit()
        self.reg_confirm_password.setEchoMode(QLineEdit.Password)
        self.reg_confirm_password.setPlaceholderText("Confirm your passphrase")
        self.reg_confirm_password.returnPressed.connect(self.handle_register)
        form_layout.addRow("Confirm:", self.reg_confirm_password)
        
        form_group.setLayout(form_layout)
        layout.addWidget(form_group)
        
        # Register button
        self.register_button = QPushButton("Register Account")
        self.register_button.clicked.connect(self.handle_register)
        layout.addWidget(self.register_button)
        
        layout.addStretch()
        widget.setLayout(layout)
        return widget
    
    def create_recovery_tab(self):
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Recovery form
        form_group = QGroupBox("Account Recovery")
        form_layout = QFormLayout()
        
        # Info text
        info_text = QLabel("Use your 16-character recovery code to reset your passphrase.\n"
                          "Warning: This will invalidate your existing RSA keys.")
        info_text.setWordWrap(True)
        info_text.setStyleSheet("color: #666; font-style: italic;")
        layout.addWidget(info_text)
        
        self.recovery_email = QLineEdit()
        self.recovery_email.setPlaceholderText("Enter your email address")
        form_layout.addRow("Email:", self.recovery_email)
        
        self.recovery_code = QLineEdit()
        self.recovery_code.setPlaceholderText("Enter 16-character recovery code")
        self.recovery_code.setMaxLength(16)
        form_layout.addRow("Recovery Code:", self.recovery_code)
        
        self.recovery_new_password = QLineEdit()
        self.recovery_new_password.setEchoMode(QLineEdit.Password)
        self.recovery_new_password.setPlaceholderText("Enter new passphrase")
        form_layout.addRow("New Passphrase:", self.recovery_new_password)
        
        self.recovery_confirm_password = QLineEdit()
        self.recovery_confirm_password.setEchoMode(QLineEdit.Password)
        self.recovery_confirm_password.setPlaceholderText("Confirm new passphrase")
        self.recovery_confirm_password.returnPressed.connect(self.handle_recovery)
        form_layout.addRow("Confirm:", self.recovery_confirm_password)
        
        form_group.setLayout(form_layout)
        layout.addWidget(form_group)
        
        # Recovery button
        self.recovery_button = QPushButton("Recover Account")
        self.recovery_button.clicked.connect(self.handle_recovery)
        layout.addWidget(self.recovery_button)
        
        layout.addStretch()
        widget.setLayout(layout)
        return widget
    
    def handle_login(self):
        email = self.login_email.text().strip()
        password = self.login_password.text()
        
        if not email or not password:
            show_error(self, "Login Error", "Please enter both email and passphrase.")
            return
        
        # Attempt login
        success, message, user_info = self.auth_manager.initiate_login_flow(email, password, gui_mode=True)
        
        if success:
            self.login_successful.emit(user_info)
        else:
            show_error(self, "Login Failed", message)
    
    def handle_register(self):
        email = self.reg_email.text().strip()
        name = self.reg_name.text().strip()
        phone = self.reg_phone.text().strip() or None
        address = self.reg_address.text().strip() or None
        birth_date = self.reg_birth_date.text().strip() or None
        password = self.reg_password.text()
        confirm_password = self.reg_confirm_password.text()
        
        if not email or not name or not password:
            show_error(self, "Registration Error", "Please fill in all required fields.")
            return
        
        if password != confirm_password:
            show_error(self, "Registration Error", "Passphrases do not match!")
            return
        
        # Attempt registration
        success, message = self.auth_manager.register_user(
            email=email, name=name, password=password,
            phone=phone, address=address, birth_date=birth_date
        )
        
        if success:
            # Show custom registration success dialog with copy functionality
            dialog = RegistrationSuccessDialog(message, self)
            dialog.exec_()
            self.clear_register_form()
            self.tab_widget.setCurrentIndex(0)  # Switch to login tab
        else:
            show_error(self, "Registration Failed", message)
    
    def handle_recovery(self):
        email = self.recovery_email.text().strip()
        recovery_code = self.recovery_code.text().strip()
        new_password = self.recovery_new_password.text()
        confirm_password = self.recovery_confirm_password.text()
        
        if not email or not recovery_code or not new_password:
            show_error(self, "Recovery Error", "Please fill in all fields.")
            return
        
        if len(recovery_code) != 16:
            show_error(self, "Recovery Error", "Recovery code must be 16 characters long.")
            return
        
        if new_password != confirm_password:
            show_error(self, "Recovery Error", "Passphrases do not match!")
            return
        
        # Attempt recovery
        success, message = self.auth_manager.recover_account_with_code(
            email, recovery_code, new_password
        )
        
        if success:
            show_info(self, "Recovery Successful", message)
            self.clear_recovery_form()
            self.tab_widget.setCurrentIndex(0)  # Switch to login tab
        else:
            show_error(self, "Recovery Failed", message)
    
    def clear_register_form(self):
        self.reg_email.clear()
        self.reg_name.clear()
        self.reg_phone.clear()
        self.reg_address.clear()
        self.reg_birth_date.clear()
        self.reg_password.clear()
        self.reg_confirm_password.clear()
    
    def clear_recovery_form(self):
        self.recovery_email.clear()
        self.recovery_code.clear()
        self.recovery_new_password.clear()
        self.recovery_confirm_password.clear()
    
    def clear_login_form(self):
        """Clear the login form fields"""
        self.login_email.clear()
        self.login_password.clear()
    
    def clear_all_forms(self):
        """Clear all form fields across all tabs"""
        self.clear_login_form()
        self.clear_register_form()
        self.clear_recovery_form()
        # Switch back to login tab
        self.tab_widget.setCurrentIndex(0)
    
    def reset_for_new_session(self):
        """Reset the screen for a new session"""
        self.clear_all_forms()
        self.tab_widget.setCurrentIndex(0)  # Ensure login tab is selected 