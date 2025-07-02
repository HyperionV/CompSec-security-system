from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QFormLayout, QLineEdit, 
                             QPushButton, QLabel, QMessageBox, QDateEdit, QTextEdit)
from PyQt5.QtCore import Qt, QDate
from PyQt5.QtGui import QFont
from modules.auth import auth_manager
from modules.database import db_manager

class RegistrationWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.setup_validation()
        
    def init_ui(self):
        self.setWindowTitle("SecurityApp - User Registration")
        self.setFixedSize(400, 500)
        
        main_layout = QVBoxLayout()
        
        title = QLabel("User Registration")
        title.setAlignment(Qt.AlignCenter)
        title.setFont(QFont("Arial", 16, QFont.Bold))
        main_layout.addWidget(title)
        
        form_layout = QFormLayout()
        
        # Email field
        self.email_input = QLineEdit()
        self.email_input.setPlaceholderText("Enter your email address")
        self.email_feedback = QLabel()
        self.email_feedback.setStyleSheet("color: red; font-size: 12px;")
        form_layout.addRow("Email:", self.email_input)
        form_layout.addRow("", self.email_feedback)
        
        # Name field
        self.name_input = QLineEdit()
        self.name_input.setPlaceholderText("Enter your full name")
        self.name_feedback = QLabel()
        self.name_feedback.setStyleSheet("color: red; font-size: 12px;")
        form_layout.addRow("Full Name:", self.name_input)
        form_layout.addRow("", self.name_feedback)
        
        # Password field
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText("8+ chars, uppercase, numbers, symbols")
        self.password_feedback = QLabel()
        self.password_feedback.setStyleSheet("color: red; font-size: 12px;")
        form_layout.addRow("Password:", self.password_input)
        form_layout.addRow("", self.password_feedback)
        
        # Phone field (optional)
        self.phone_input = QLineEdit()
        self.phone_input.setPlaceholderText("Phone number (optional)")
        form_layout.addRow("Phone:", self.phone_input)
        
        # Address field (optional)
        self.address_input = QTextEdit()
        self.address_input.setPlaceholderText("Address (optional)")
        self.address_input.setMaximumHeight(80)
        form_layout.addRow("Address:", self.address_input)
        
        # Birth date field (optional)
        self.birth_date_input = QDateEdit()
        self.birth_date_input.setDate(QDate.currentDate().addYears(-18))
        self.birth_date_input.setCalendarPopup(True)
        form_layout.addRow("Birth Date:", self.birth_date_input)
        
        main_layout.addLayout(form_layout)
        
        # Register button
        self.register_button = QPushButton("Register")
        self.register_button.setEnabled(False)
        self.register_button.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                padding: 10px;
                font-size: 14px;
                border-radius: 5px;
            }
            QPushButton:disabled {
                background-color: #cccccc;
            }
            QPushButton:hover:enabled {
                background-color: #45a049;
            }
        """)
        self.register_button.clicked.connect(self.register_user)
        main_layout.addWidget(self.register_button)
        
        self.setLayout(main_layout)
    
    def setup_validation(self):
        self.email_input.textChanged.connect(self.validate_form)
        self.name_input.textChanged.connect(self.validate_form)
        self.password_input.textChanged.connect(self.validate_form)
    
    def validate_form(self):
        email_valid = self.validate_email()
        name_valid = self.validate_name()
        password_valid = self.validate_password()
        
        # Enable register button only if all required fields are valid
        self.register_button.setEnabled(email_valid and name_valid and password_valid)
    
    def validate_email(self):
        email = self.email_input.text()
        valid, message = auth_manager.validate_email(email)
        
        if email and not valid:
            self.email_feedback.setText(message)
            self.email_feedback.setStyleSheet("color: red; font-size: 12px;")
        elif email and valid:
            self.email_feedback.setText("✓ Valid email")
            self.email_feedback.setStyleSheet("color: green; font-size: 12px;")
        else:
            self.email_feedback.setText("")
            
        return valid and email
    
    def validate_name(self):
        name = self.name_input.text()
        valid, message = auth_manager.validate_name(name)
        
        if name and not valid:
            self.name_feedback.setText(message)
            self.name_feedback.setStyleSheet("color: red; font-size: 12px;")
        elif name and valid:
            self.name_feedback.setText("✓ Valid name")
            self.name_feedback.setStyleSheet("color: green; font-size: 12px;")
        else:
            self.name_feedback.setText("")
            
        return valid and name
    
    def validate_password(self):
        password = self.password_input.text()
        valid, message = auth_manager.validate_password(password)
        
        if password and not valid:
            self.password_feedback.setText(message)
            self.password_feedback.setStyleSheet("color: red; font-size: 12px;")
        elif password and valid:
            self.password_feedback.setText("✓ Strong password")
            self.password_feedback.setStyleSheet("color: green; font-size: 12px;")
        else:
            self.password_feedback.setText("")
            
        return valid and password
    
    def register_user(self):
        # Initialize database tables
        db_manager.create_tables()
        
        email = self.email_input.text().strip()
        name = self.name_input.text().strip()
        password = self.password_input.text()
        phone = self.phone_input.text().strip() or None
        address = self.address_input.toPlainText().strip() or None
        birth_date = self.birth_date_input.date().toPyDate()
        
        success, message = auth_manager.register_user(email, name, password, phone, address, birth_date)
        
        if success:
            QMessageBox.information(self, "Registration Successful", 
                                   f"Account created successfully!\n\nEmail: {email}\nName: {name}")
            self.clear_form()
        else:
            QMessageBox.warning(self, "Registration Failed", message)
    
    def clear_form(self):
        self.email_input.clear()
        self.name_input.clear()
        self.password_input.clear()
        self.phone_input.clear()
        self.address_input.clear()
        self.birth_date_input.setDate(QDate.currentDate().addYears(-18))
        self.email_feedback.clear()
        self.name_feedback.clear()
        self.password_feedback.clear() 