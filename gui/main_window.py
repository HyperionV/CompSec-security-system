from PyQt5.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                             QLabel, QPushButton, QMenuBar, QAction, QMessageBox)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont
from modules.session import session_manager
from modules.auth import setup_totp_for_user, verify_totp_for_user
from modules.database import db_manager
from gui.qr_code_dialog import show_qr_code_dialog

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.init_ui()
        
    def init_ui(self):
        self.setWindowTitle("SecurityApp - Main Dashboard")
        self.setGeometry(100, 100, 800, 600)
        
        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        layout = QVBoxLayout()
        
        # Welcome section
        welcome_layout = QVBoxLayout()
        
        if session_manager.is_logged_in():
            user = session_manager.get_current_user()
            welcome_title = QLabel(f"Welcome, {user['name']}!")
            welcome_title.setFont(QFont("Arial", 20, QFont.Bold))
            welcome_title.setAlignment(Qt.AlignCenter)
            welcome_title.setStyleSheet("color: #2c3e50; margin: 20px;")
            
            user_info = QLabel(f"Email: {user['email']} | Role: {user['role'].upper()}")
            user_info.setFont(QFont("Arial", 12))
            user_info.setAlignment(Qt.AlignCenter)
            user_info.setStyleSheet("color: #7f8c8d; margin-bottom: 30px;")
            
            welcome_layout.addWidget(welcome_title)
            welcome_layout.addWidget(user_info)
        else:
            welcome_title = QLabel("SecurityApp Dashboard")
            welcome_title.setFont(QFont("Arial", 20, QFont.Bold))
            welcome_title.setAlignment(Qt.AlignCenter)
            welcome_title.setStyleSheet("color: #2c3e50; margin: 20px;")
            welcome_layout.addWidget(welcome_title)
        
        layout.addLayout(welcome_layout)
        
        # Status section
        status_label = QLabel("🔒 Core Authentication System - Active")
        status_label.setFont(QFont("Arial", 14))
        status_label.setAlignment(Qt.AlignCenter)
        status_label.setStyleSheet("""
            background-color: #d5f4e6;
            color: #27ae60;
            padding: 15px;
            border-radius: 8px;
            border: 2px solid #27ae60;
            margin: 20px;
        """)
        layout.addWidget(status_label)
        
        # Security features section (new)
        if session_manager.is_logged_in():
            security_label = QLabel("🔐 Security Features:")
            security_label.setFont(QFont("Arial", 16, QFont.Bold))
            security_label.setStyleSheet("color: #2c3e50; margin: 20px 20px 10px 20px;")
            layout.addWidget(security_label)
            
            # TOTP Setup button
            totp_setup_btn = QPushButton("📱 Setup TOTP Authentication")
            totp_setup_btn.setFixedSize(280, 45)
            totp_setup_btn.setStyleSheet("""
                QPushButton {
                    background-color: #4CAF50;
                    color: white;
                    border: none;
                    padding: 12px 20px;
                    border-radius: 8px;
                    font-size: 14px;
                    font-weight: bold;
                }
                QPushButton:hover {
                    background-color: #45a049;
                }
            """)
            totp_setup_btn.clicked.connect(self.setup_totp)
            
            # Center the button
            totp_layout = QHBoxLayout()
            totp_layout.addStretch()
            totp_layout.addWidget(totp_setup_btn)
            totp_layout.addStretch()
            
            layout.addLayout(totp_layout)
        
        # Features section
        features_label = QLabel("🚀 Available Features:")
        features_label.setFont(QFont("Arial", 16, QFont.Bold))
        features_label.setStyleSheet("color: #2c3e50; margin: 20px 20px 10px 20px;")
        layout.addWidget(features_label)
        
        features_list = QLabel("""
        ✅ User Registration & Authentication
        ✅ Secure Password Hashing (SHA-256 + Salt)
        ✅ Session Management
        ✅ Security Event Logging
        
        🔄 Coming Soon:
        • OTP/TOTP Authentication
        • RSA Key Management  
        • File Encryption/Decryption
        • Digital Signatures
        """)
        features_list.setFont(QFont("Arial", 12))
        features_list.setStyleSheet("color: #34495e; margin: 10px 40px; line-height: 1.6;")
        layout.addWidget(features_list)
        
        # Logout button
        logout_btn = QPushButton("Logout")
        logout_btn.setFixedSize(120, 40)
        logout_btn.setStyleSheet("""
            QPushButton {
                background-color: #e74c3c;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 5px;
                font-size: 14px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #c0392b;
            }
        """)
        logout_btn.clicked.connect(self.logout)
        
        logout_layout = QHBoxLayout()
        logout_layout.addStretch()
        logout_layout.addWidget(logout_btn)
        logout_layout.addStretch()
        
        layout.addStretch()
        layout.addLayout(logout_layout)
        
        central_widget.setLayout(layout)
        
        # Create menu bar
        self.create_menu_bar()
    
    def create_menu_bar(self):
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu('File')
        
        logout_action = QAction('Logout', self)
        logout_action.triggered.connect(self.logout)
        file_menu.addAction(logout_action)
        
        exit_action = QAction('Exit', self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Security menu (new)
        security_menu = menubar.addMenu('Security')
        
        totp_setup_action = QAction('Setup TOTP Authentication', self)
        totp_setup_action.triggered.connect(self.setup_totp)
        security_menu.addAction(totp_setup_action)
        
        # Help menu
        help_menu = menubar.addMenu('Help')
        
        about_action = QAction('About', self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
    
    def logout(self):
        reply = QMessageBox.question(self, 'Logout', 'Are you sure you want to logout?',
                                   QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        
        if reply == QMessageBox.Yes:
            session_manager.logout()
            QMessageBox.information(self, "Logout", "You have been logged out successfully.")
            self.close()
            
            # Import here to avoid circular import
            from gui.login_window import LoginWindow
            self.login_window = LoginWindow()
            self.login_window.show()
    
    def show_about(self):
        QMessageBox.about(self, "About SecurityApp", 
                         "SecurityApp v1.0.0\n\n"
                         "A comprehensive desktop security application\n"
                         "Built with Python, PyQt5, and MySQL\n\n"
                         "Features secure authentication, encryption,\n"
                         "and file management capabilities.")
    
    def closeEvent(self, event):
        reply = QMessageBox.question(self, 'Exit Application', 
                                   'Are you sure you want to exit?',
                                   QMessageBox.Yes | QMessageBox.No, 
                                   QMessageBox.No)
        
        if reply == QMessageBox.Yes:
            if session_manager.is_logged_in():
                session_manager.logout()
            event.accept()
        else:
            event.ignore()

    def setup_totp(self):
        """Setup TOTP authentication for the current user"""
        if not session_manager.is_logged_in():
            QMessageBox.warning(self, "Error", "You must be logged in to setup TOTP authentication.")
            return
        
        user = session_manager.get_current_user()
        user_id = user['id']
        user_email = user['email']
        
        # Check if user already has TOTP setup
        existing_secret = db_manager.get_user_totp_secret(user_id)
        if existing_secret:
            reply = QMessageBox.question(self, 'TOTP Already Setup', 
                                       'TOTP authentication is already configured for your account.\n\n'
                                       'Do you want to generate a new QR code?',
                                       QMessageBox.Yes | QMessageBox.No, 
                                       QMessageBox.No)
            if reply != QMessageBox.Yes:
                return
        
        try:
            # Setup TOTP for user
            qr_image_path, secret = setup_totp_for_user(user_id)
            
            if qr_image_path and secret:
                # Show QR code dialog
                show_qr_code_dialog(qr_image_path, user_email, secret, self)
                
                QMessageBox.information(self, "TOTP Setup Complete", 
                                      "TOTP authentication has been successfully configured!\n\n"
                                      "• Scan the QR code with Google Authenticator or similar app\n"
                                      "• Your TOTP secret has been securely stored\n"
                                      "• You can now use TOTP codes for enhanced security")
            else:
                QMessageBox.critical(self, "Setup Failed", 
                                   "Failed to setup TOTP authentication. Please try again.")
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"An error occurred during TOTP setup:\n{str(e)}") 