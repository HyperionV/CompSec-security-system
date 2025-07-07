from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, 
                             QPushButton, QLabel, QTextEdit, QProgressBar)
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QFont
from ..utils.dialogs import show_error, show_info, show_warning, show_question, PasswordDialog

class KeyManagementTab(QWidget):
    def __init__(self, user_session, managers, parent=None):
        super().__init__(parent)
        self.user_session = user_session
        self.managers = managers
        self.key_manager = managers['key_manager']
        self.auth_manager = managers['auth_manager']
        self.db = managers['db']
        
        # Timer for periodic key status updates
        self.status_timer = QTimer()
        self.status_timer.timeout.connect(self.update_key_status)
        self.status_timer.start(30000)  # Update every 30 seconds
        
        self.setup_ui()
        self.update_key_status()
    
    def setup_ui(self):
        layout = QVBoxLayout()
        
        # Key Status Section
        status_group = QGroupBox("Current Key Status")
        status_layout = QVBoxLayout()
        
        self.status_label = QLabel("Loading key status...")
        self.status_label.setWordWrap(True)
        status_layout.addWidget(self.status_label)
        
        # Key details text area
        self.key_details = QTextEdit()
        self.key_details.setReadOnly(True)
        self.key_details.setMaximumHeight(150)
        self.key_details.setFont(QFont("Courier", 9))
        status_layout.addWidget(self.key_details)
        
        status_group.setLayout(status_layout)
        layout.addWidget(status_group)
        
        # Key Actions Section
        actions_group = QGroupBox("Key Management Actions")
        actions_layout = QVBoxLayout()
        
        # Generate/Renew buttons
        button_layout = QHBoxLayout()
        
        self.generate_button = QPushButton("Generate New Keys")
        self.generate_button.clicked.connect(self.generate_keys)
        button_layout.addWidget(self.generate_button)
        
        self.renew_button = QPushButton("Renew Existing Keys")
        self.renew_button.clicked.connect(self.renew_keys)
        button_layout.addWidget(self.renew_button)
        
        actions_layout.addLayout(button_layout)
        
        # Security info button
        self.security_info_button = QPushButton("View Key Security Information")
        self.security_info_button.clicked.connect(self.show_security_info)
        actions_layout.addWidget(self.security_info_button)
        
        actions_group.setLayout(actions_layout)
        layout.addWidget(actions_group)
        
        # Progress section (hidden by default)
        self.progress_group = QGroupBox("Key Generation Progress")
        progress_layout = QVBoxLayout()
        
        self.progress_label = QLabel("")
        progress_layout.addWidget(self.progress_label)
        
        self.progress_bar = QProgressBar()
        progress_layout.addWidget(self.progress_bar)
        
        self.progress_group.setLayout(progress_layout)
        self.progress_group.hide()
        layout.addWidget(self.progress_group)
        
        layout.addStretch()
        self.setLayout(layout)
    
    def update_key_status(self):
        """Update the current key status display"""
        try:
            user_id = self.user_session.user_info['id']
            
            # Get user's keys
            keys = self.db.get_user_keys_by_id(user_id)
            
            if not keys:
                self.status_label.setText("❌ No RSA keys found")
                self.status_label.setStyleSheet("color: red; font-weight: bold;")
                self.key_details.setText("No keys available. Please generate new keys.")
                self.generate_button.setEnabled(True)
                self.renew_button.setEnabled(False)
                return
            
            # Get the most recent key
            latest_key = keys[0]  # Assuming keys are ordered by creation date
            
            # Check key status
            from datetime import datetime
            expires_at = datetime.fromisoformat(latest_key['expires_at'])
            now = datetime.now()
            days_until_expiry = (expires_at - now).days
            
            # Update status based on expiration
            if days_until_expiry < 0:
                status_text = f"🔴 Keys EXPIRED {abs(days_until_expiry)} days ago"
                status_color = "color: red; font-weight: bold;"
                self.generate_button.setEnabled(True)
                self.renew_button.setEnabled(True)
            elif days_until_expiry <= 7:
                status_text = f"🟡 Keys expiring in {days_until_expiry} days"
                status_color = "color: orange; font-weight: bold;"
                self.generate_button.setEnabled(True)
                self.renew_button.setEnabled(True)
            else:
                status_text = f"✅ Keys valid ({days_until_expiry} days remaining)"
                status_color = "color: green; font-weight: bold;"
                self.generate_button.setEnabled(True)
                self.renew_button.setEnabled(True)
            
            self.status_label.setText(status_text)
            self.status_label.setStyleSheet(status_color)
            
            # Update key details
            details = f"Key ID: {latest_key['id']}\n"
            details += f"Created: {latest_key['created_at'].split('T')[0]}\n"
            details += f"Expires: {latest_key['expires_at'].split('T')[0]}\n"
            details += f"Status: {latest_key['status'].upper()}\n"
            details += f"Algorithm: RSA-2048"
            
            self.key_details.setText(details)
            
        except Exception as e:
            self.status_label.setText(f"Error loading key status: {str(e)}")
            self.status_label.setStyleSheet("color: red;")
    
    def generate_keys(self):
        """Generate new RSA keys"""
        if not show_question(self, "Generate Keys", 
                           "This will create new RSA keys. Any existing keys will remain but new keys will be used for future operations. Continue?"):
            return
        
        # Get passphrase
        password_dialog = PasswordDialog("Generate Keys", "Enter your account passphrase:", self)
        if password_dialog.exec_() != password_dialog.Accepted:
            return
        
        passphrase = password_dialog.get_password()
        if not passphrase:
            show_error(self, "Error", "Passphrase is required.")
            return
        
        try:
            # Show progress
            self.show_progress("Generating RSA keys...", 0)
            
            # Generate keys
            success, message = self.auth_manager.generate_new_keys(
                self.user_session.user_info['id'], passphrase
            )
            
            self.hide_progress()
            
            if success:
                show_info(self, "Success", message)
                self.update_key_status()
            else:
                show_error(self, "Generation Failed", message)
                
        except Exception as e:
            self.hide_progress()
            show_error(self, "Error", f"Failed to generate keys: {str(e)}")
    
    def renew_keys(self):
        """Renew existing RSA keys"""
        if not show_question(self, "Renew Keys", 
                           "This will renew your existing RSA keys with a new expiration date. Continue?"):
            return
        
        # Get passphrase
        password_dialog = PasswordDialog("Renew Keys", "Enter your account passphrase:", self)
        if password_dialog.exec_() != password_dialog.Accepted:
            return
        
        passphrase = password_dialog.get_password()
        if not passphrase:
            show_error(self, "Error", "Passphrase is required.")
            return
        
        try:
            # Show progress
            self.show_progress("Renewing RSA keys...", 0)
            
            # Renew keys
            success, message = self.auth_manager.renew_user_keys(
                self.user_session.user_info['id'], passphrase
            )
            
            self.hide_progress()
            
            if success:
                show_info(self, "Success", message)
                self.update_key_status()
            else:
                show_error(self, "Renewal Failed", message)
                
        except Exception as e:
            self.hide_progress()
            show_error(self, "Error", f"Failed to renew keys: {str(e)}")
    
    def show_security_info(self):
        """Show key security information"""
        info_text = """RSA Key Security Information

Key Algorithm: RSA-2048
- RSA keys use 2048-bit key size for strong security
- Public key is used for encryption and signature verification
- Private key is used for decryption and digital signing

Key Lifecycle:
- Keys are valid for 90 days from creation
- Warning notifications start 7 days before expiration
- Expired keys should be renewed or regenerated
- Old keys remain available for decrypting old files

Security Best Practices:
- Keep your passphrase secure and unique
- Generate new keys periodically (every 90 days)
- Back up important encrypted files before key changes
- Export public keys via QR code for sharing
- Never share your private key or passphrase

Encryption Process:
- Your public key encrypts data for you
- Your private key decrypts data encrypted with your public key
- Others' public keys encrypt data for them
- Digital signatures prove authenticity and integrity

Key Storage:
- Private keys are encrypted with your passphrase
- Public keys are stored for encryption operations
- All keys are stored securely in the local database
- Key metadata includes creation and expiration dates"""

        from ..utils.dialogs import InfoDialog
        dialog = InfoDialog("Key Security Information", info_text, self)
        dialog.exec_()
    
    def show_progress(self, message, value):
        """Show progress bar with message"""
        self.progress_label.setText(message)
        self.progress_bar.setValue(value)
        self.progress_group.show()
    
    def hide_progress(self):
        """Hide progress bar"""
        self.progress_group.hide()
    
    def refresh_data(self):
        """Refresh key status"""
        self.update_key_status() 