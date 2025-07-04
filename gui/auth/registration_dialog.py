"""
RegistrationDialog - User registration interface for SecurityApp

This module provides the registration dialog for new users to create accounts.
It integrates with the existing auth.py module through the AuthController and
provides real-time validation and user feedback.
"""

from PyQt5.QtWidgets import (QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, 
                             QPushButton, QProgressBar, QFrame)
from PyQt5.QtCore import Qt, QRegExp, QTimer
from PyQt5.QtGui import QRegExpValidator, QFont

from ..base.base_dialog import BaseDialog
from ..utils.message_boxes import MessageBoxes
import re


class RegistrationDialog(BaseDialog):
    """
    Registration dialog for creating new user accounts.
    
    This dialog handles:
    - New user registration with validation
    - Real-time password strength checking
    - Email format validation
    - Username availability checking
    - Integration with auth.py module
    """
    
    def __init__(self, auth_controller, parent=None):
        self.auth_controller = auth_controller
        self.username = None  # Store successful registration username
        super().__init__("Create New Account", parent)
        self.setup_ui()
        self.setup_connections()
        self.setup_validation()
        
    def setup_ui(self):
        """Setup the registration dialog UI."""
        self.setWindowTitle("Create New Account")
        self.setFixedSize(450, 600)
        
        layout = QVBoxLayout()
        layout.setSpacing(20)
        layout.setContentsMargins(30, 30, 30, 30)
        
        # Header
        header_layout = self.create_header()
        layout.addLayout(header_layout)
        
        # Registration form
        form_layout = self.create_registration_form()
        layout.addLayout(form_layout)
        
        # Password strength indicator
        strength_layout = self.create_password_strength_section()
        layout.addLayout(strength_layout)
        
        # Action buttons
        button_layout = self.create_action_buttons()
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
        
    def create_header(self):
        """Create the header section."""
        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignCenter)
        
        title_label = QLabel("Create New Account")
        title_font = QFont()
        title_font.setPointSize(18)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setStyleSheet("color: #2c3e50; margin-bottom: 10px;")
        layout.addWidget(title_label)
        
        subtitle_label = QLabel("Please fill in all fields to create your account")
        subtitle_label.setAlignment(Qt.AlignCenter)
        subtitle_label.setStyleSheet("color: #7f8c8d; margin-bottom: 20px;")
        layout.addWidget(subtitle_label)
        
        return layout
        
    def create_registration_form(self):
        """Create the registration form fields."""
        layout = QVBoxLayout()
        layout.setSpacing(15)
        
        # Username field
        username_label = QLabel("Username:")
        username_label.setStyleSheet("font-weight: bold; color: #2c3e50;")
        layout.addWidget(username_label)
        
        self.username_field = QLineEdit()
        self.username_field.setPlaceholderText("Choose a unique username")
        self.username_field.setStyleSheet(self.get_field_style())
        layout.addWidget(self.username_field)
        
        # Username validation label
        self.username_validation_label = QLabel("")
        self.username_validation_label.setStyleSheet("font-size: 10px; margin-top: -10px;")
        layout.addWidget(self.username_validation_label)
        
        # Email field
        email_label = QLabel("Email Address:")
        email_label.setStyleSheet("font-weight: bold; color: #2c3e50;")
        layout.addWidget(email_label)
        
        self.email_field = QLineEdit()
        self.email_field.setPlaceholderText("Enter your email address")
        self.email_field.setStyleSheet(self.get_field_style())
        layout.addWidget(self.email_field)
        
        # Email validation label
        self.email_validation_label = QLabel("")
        self.email_validation_label.setStyleSheet("font-size: 10px; margin-top: -10px;")
        layout.addWidget(self.email_validation_label)
        
        # Passphrase field
        passphrase_label = QLabel("Passphrase:")
        passphrase_label.setStyleSheet("font-weight: bold; color: #2c3e50;")
        layout.addWidget(passphrase_label)
        
        self.passphrase_field = QLineEdit()
        self.passphrase_field.setPlaceholderText("Create a strong passphrase")
        self.passphrase_field.setEchoMode(QLineEdit.Password)
        self.passphrase_field.setStyleSheet(self.get_field_style())
        layout.addWidget(self.passphrase_field)
        
        # Confirm passphrase field
        confirm_label = QLabel("Confirm Passphrase:")
        confirm_label.setStyleSheet("font-weight: bold; color: #2c3e50;")
        layout.addWidget(confirm_label)
        
        self.confirm_passphrase_field = QLineEdit()
        self.confirm_passphrase_field.setPlaceholderText("Confirm your passphrase")
        self.confirm_passphrase_field.setEchoMode(QLineEdit.Password)
        self.confirm_passphrase_field.setStyleSheet(self.get_field_style())
        layout.addWidget(self.confirm_passphrase_field)
        
        # Passphrase confirmation label
        self.passphrase_match_label = QLabel("")
        self.passphrase_match_label.setStyleSheet("font-size: 10px; margin-top: -10px;")
        layout.addWidget(self.passphrase_match_label)
        
        return layout
        
    def create_password_strength_section(self):
        """Create the password strength indicator section."""
        layout = QVBoxLayout()
        layout.setSpacing(5)
        
        # Strength label
        strength_label = QLabel("Passphrase Strength:")
        strength_label.setStyleSheet("font-weight: bold; color: #2c3e50; font-size: 11px;")
        layout.addWidget(strength_label)
        
        # Strength progress bar
        self.strength_progress = QProgressBar()
        self.strength_progress.setMaximum(100)
        self.strength_progress.setValue(0)
        self.strength_progress.setStyleSheet("""
            QProgressBar {
                border: 2px solid #bdc3c7;
                border-radius: 5px;
                text-align: center;
                font-size: 10px;
                height: 20px;
            }
            QProgressBar::chunk {
                background-color: #e74c3c;
                border-radius: 3px;
            }
        """)
        layout.addWidget(self.strength_progress)
        
        # Strength text
        self.strength_text_label = QLabel("Enter a passphrase to check strength")
        self.strength_text_label.setStyleSheet("font-size: 10px; color: #7f8c8d;")
        layout.addWidget(self.strength_text_label)
        
        return layout
        
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
        
        # Create account button
        self.create_button = QPushButton("Create Account")
        self.create_button.setStyleSheet("""
            QPushButton {
                background-color: #27ae60;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 5px;
                font-size: 12px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #229954;
            }
            QPushButton:disabled {
                background-color: #bdc3c7;
            }
        """)
        self.create_button.clicked.connect(self.handle_registration)
        self.create_button.setEnabled(False)
        layout.addWidget(self.create_button)
        
        return layout
        
    def setup_connections(self):
        """Setup signal/slot connections."""
        # Real-time validation
        self.username_field.textChanged.connect(self.validate_username)
        self.email_field.textChanged.connect(self.validate_email)
        self.passphrase_field.textChanged.connect(self.validate_passphrase)
        self.confirm_passphrase_field.textChanged.connect(self.validate_passphrase_match)
        
        # Validation timer for username availability check
        self.username_timer = QTimer()
        self.username_timer.setSingleShot(True)
        self.username_timer.timeout.connect(self.check_username_availability)
        
    def setup_validation(self):
        """Setup form validation."""
        # Email regex validator
        email_regex = QRegExp(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
        self.email_validator = QRegExpValidator(email_regex)
        
        # Initialize validation state
        self.validation_state = {
            'username': False,
            'email': False,
            'passphrase': False,
            'passphrase_match': False
        }
        
    def get_field_style(self):
        """Get the standard field styling."""
        return """
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
        """
        
    def validate_username(self):
        """Validate username field."""
        username = self.username_field.text().strip()
        
        if not username:
            self.username_validation_label.setText("")
            self.validation_state['username'] = False
        elif len(username) < 3:
            self.username_validation_label.setText("Username must be at least 3 characters")
            self.username_validation_label.setStyleSheet("color: #e74c3c; font-size: 10px;")
            self.validation_state['username'] = False
        elif not re.match(r'^[a-zA-Z0-9_]+$', username):
            self.username_validation_label.setText("Username can only contain letters, numbers, and underscores")
            self.username_validation_label.setStyleSheet("color: #e74c3c; font-size: 10px;")
            self.validation_state['username'] = False
        else:
            self.username_validation_label.setText("Checking availability...")
            self.username_validation_label.setStyleSheet("color: #f39c12; font-size: 10px;")
            # Delay username availability check
            self.username_timer.start(500)
            
        self.update_create_button()
        
    def check_username_availability(self):
        """Check if username is available."""
        username = self.username_field.text().strip()
        
        try:
            is_available = self.auth_controller.check_username_availability(username)
            
            if is_available:
                self.username_validation_label.setText("✓ Username available")
                self.username_validation_label.setStyleSheet("color: #27ae60; font-size: 10px;")
                self.validation_state['username'] = True
            else:
                self.username_validation_label.setText("✗ Username already taken")
                self.username_validation_label.setStyleSheet("color: #e74c3c; font-size: 10px;")
                self.validation_state['username'] = False
                
        except Exception as e:
            self.username_validation_label.setText("Error checking availability")
            self.username_validation_label.setStyleSheet("color: #e74c3c; font-size: 10px;")
            self.validation_state['username'] = False
            
        self.update_create_button()
        
    def validate_email(self):
        """Validate email field."""
        email = self.email_field.text().strip()
        
        if not email:
            self.email_validation_label.setText("")
            self.validation_state['email'] = False
        elif self.email_validator.validate(email, 0)[0] != QRegExpValidator.Acceptable:
            self.email_validation_label.setText("✗ Invalid email format")
            self.email_validation_label.setStyleSheet("color: #e74c3c; font-size: 10px;")
            self.validation_state['email'] = False
        else:
            self.email_validation_label.setText("✓ Valid email format")
            self.email_validation_label.setStyleSheet("color: #27ae60; font-size: 10px;")
            self.validation_state['email'] = True
            
        self.update_create_button()
        
    def validate_passphrase(self):
        """Validate passphrase and update strength indicator."""
        passphrase = self.passphrase_field.text()
        
        if not passphrase:
            self.strength_progress.setValue(0)
            self.strength_text_label.setText("Enter a passphrase to check strength")
            self.strength_text_label.setStyleSheet("font-size: 10px; color: #7f8c8d;")
            self.validation_state['passphrase'] = False
        else:
            strength = self.calculate_password_strength(passphrase)
            self.update_strength_display(strength)
            self.validation_state['passphrase'] = strength >= 60  # Minimum acceptable strength
            
        self.validate_passphrase_match()  # Also check if passwords match
        self.update_create_button()
        
    def calculate_password_strength(self, passphrase):
        """Calculate password strength score (0-100)."""
        score = 0
        
        # Length bonus
        if len(passphrase) >= 8:
            score += 20
        if len(passphrase) >= 12:
            score += 10
        if len(passphrase) >= 16:
            score += 10
            
        # Character variety
        if re.search(r'[a-z]', passphrase):
            score += 10
        if re.search(r'[A-Z]', passphrase):
            score += 10
        if re.search(r'\d', passphrase):
            score += 10
        if re.search(r'[^a-zA-Z0-9]', passphrase):
            score += 15
            
        # Patterns (deduct points for common patterns)
        if re.search(r'(.)\1{2,}', passphrase):  # Repeated characters
            score -= 10
        if re.search(r'(012|123|234|345|456|567|678|789|890)', passphrase):
            score -= 10
        if re.search(r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)', passphrase.lower()):
            score -= 10
            
        return min(100, max(0, score))
        
    def update_strength_display(self, strength):
        """Update the password strength display."""
        self.strength_progress.setValue(strength)
        
        if strength < 30:
            color = "#e74c3c"
            text = "Weak"
            self.strength_progress.setStyleSheet(self.get_progress_style(color))
        elif strength < 60:
            color = "#f39c12"
            text = "Fair"
            self.strength_progress.setStyleSheet(self.get_progress_style(color))
        elif strength < 80:
            color = "#f1c40f"
            text = "Good"
            self.strength_progress.setStyleSheet(self.get_progress_style(color))
        else:
            color = "#27ae60"
            text = "Strong"
            self.strength_progress.setStyleSheet(self.get_progress_style(color))
            
        self.strength_text_label.setText(f"{text} ({strength}%)")
        self.strength_text_label.setStyleSheet(f"font-size: 10px; color: {color};")
        
    def get_progress_style(self, color):
        """Get progress bar style with specific color."""
        return f"""
            QProgressBar {{
                border: 2px solid #bdc3c7;
                border-radius: 5px;
                text-align: center;
                font-size: 10px;
                height: 20px;
            }}
            QProgressBar::chunk {{
                background-color: {color};
                border-radius: 3px;
            }}
        """
        
    def validate_passphrase_match(self):
        """Validate that passphrases match."""
        passphrase = self.passphrase_field.text()
        confirm = self.confirm_passphrase_field.text()
        
        if not confirm:
            self.passphrase_match_label.setText("")
            self.validation_state['passphrase_match'] = False
        elif passphrase != confirm:
            self.passphrase_match_label.setText("✗ Passphrases do not match")
            self.passphrase_match_label.setStyleSheet("color: #e74c3c; font-size: 10px;")
            self.validation_state['passphrase_match'] = False
        else:
            self.passphrase_match_label.setText("✓ Passphrases match")
            self.passphrase_match_label.setStyleSheet("color: #27ae60; font-size: 10px;")
            self.validation_state['passphrase_match'] = True
            
        self.update_create_button()
        
    def update_create_button(self):
        """Update the create button state based on validation."""
        all_valid = all(self.validation_state.values())
        self.create_button.setEnabled(all_valid)
        
    def handle_registration(self):
        """Handle the registration process."""
        if not all(self.validation_state.values()):
            MessageBoxes.warning(self, "Validation Error", 
                                "Please correct all validation errors before proceeding.")
            return
            
        username = self.username_field.text().strip()
        email = self.email_field.text().strip()
        passphrase = self.passphrase_field.text()
        
        try:
            # Disable UI during registration
            self.set_ui_enabled(False)
            
            # Attempt registration
            result = self.auth_controller.register_user(username, email, passphrase)
            
            if result['success']:
                self.username = username  # Store for parent window
                MessageBoxes.info(self, "Registration Successful", 
                                "Account created successfully! You can now log in.")
                self.accept()
            else:
                error_msg = result.get('message', 'Registration failed')
                MessageBoxes.show_error(self, "Registration Failed", error_msg)
                
        except Exception as e:
            MessageBoxes.show_error(self, "Registration Error", 
                             f"An error occurred during registration: {str(e)}")
        finally:
            self.set_ui_enabled(True)
            
    def set_ui_enabled(self, enabled):
        """Enable or disable UI elements during processing."""
        self.username_field.setEnabled(enabled)
        self.email_field.setEnabled(enabled)
        self.passphrase_field.setEnabled(enabled)
        self.confirm_passphrase_field.setEnabled(enabled)
        self.create_button.setEnabled(enabled and all(self.validation_state.values())) 
