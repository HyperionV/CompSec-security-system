from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, 
                             QPushButton, QLabel, QTextEdit, QProgressBar, QTabWidget, 
                             QFileDialog, QMessageBox, QScrollArea)
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QFont
import base64
import json
import os
from datetime import datetime
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
        
        # Key metadata display
        self.key_metadata = QTextEdit()
        self.key_metadata.setReadOnly(True)
        self.key_metadata.setMaximumHeight(120)
        self.key_metadata.setFont(QFont("Courier", 9))
        status_layout.addWidget(self.key_metadata)
        
        status_group.setLayout(status_layout)
        layout.addWidget(status_group)
        
        # Key Display Section with Tabs
        keys_group = QGroupBox("Key Content")
        keys_layout = QVBoxLayout()
        
        # Create tab widget for public/private keys
        self.key_tabs = QTabWidget()
        
        # Public Key Tab
        public_tab = QWidget()
        public_layout = QVBoxLayout()
        
        # Public key display
        self.public_key_text = QTextEdit()
        self.public_key_text.setReadOnly(True)
        self.public_key_text.setFont(QFont("Courier", 8))
        self.public_key_text.setMaximumHeight(200)
        public_layout.addWidget(self.public_key_text)
        
        # Public key buttons
        public_buttons = QHBoxLayout()
        self.save_public_pem_btn = QPushButton("Save Public Key as .pem")
        self.save_public_pem_btn.clicked.connect(self.save_public_key_pem)
        self.copy_public_btn = QPushButton("Copy Public Key")
        self.copy_public_btn.clicked.connect(self.copy_public_key)
        public_buttons.addWidget(self.save_public_pem_btn)
        public_buttons.addWidget(self.copy_public_btn)
        public_layout.addLayout(public_buttons)
        
        public_tab.setLayout(public_layout)
        self.key_tabs.addTab(public_tab, "Public Key")
        
        # Private Key Tab
        private_tab = QWidget()
        private_layout = QVBoxLayout()
        
        # Private key display
        self.private_key_text = QTextEdit()
        self.private_key_text.setReadOnly(True)
        self.private_key_text.setFont(QFont("Courier", 8))
        self.private_key_text.setMaximumHeight(200)
        private_layout.addWidget(self.private_key_text)
        
        # Private key buttons
        private_buttons = QHBoxLayout()
        self.view_private_btn = QPushButton("View Private Key")
        self.view_private_btn.clicked.connect(self.view_private_key)
        self.save_private_pem_btn = QPushButton("Save Private Key as .pem")
        self.save_private_pem_btn.clicked.connect(self.save_private_key_pem)
        self.copy_private_btn = QPushButton("Copy Private Key")
        self.copy_private_btn.clicked.connect(self.copy_private_key)
        private_buttons.addWidget(self.view_private_btn)
        private_buttons.addWidget(self.save_private_pem_btn)
        private_buttons.addWidget(self.copy_private_btn)
        private_layout.addLayout(private_buttons)
        
        private_tab.setLayout(private_layout)
        self.key_tabs.addTab(private_tab, "Private Key")
        
        keys_layout.addWidget(self.key_tabs)
        keys_group.setLayout(keys_layout)
        layout.addWidget(keys_group)
        
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
        
        # Initialize private key display
        self.current_private_key = None
        self.private_key_text.setText("Click 'View Private Key' to display private key content")
    
    def update_key_status(self):
        """Update the current key status display"""
        try:
            user_id = self.user_session.user_info['id']
            
            # Get user's keys
            keys = self.db.get_user_keys_by_id(user_id)
            
            if not keys:
                self.status_label.setText("❌ No RSA keys found")
                self.status_label.setStyleSheet("color: red; font-weight: bold;")
                self.key_metadata.setText("No keys available. Please generate new keys.")
                self.public_key_text.setText("No public key available")
                self.private_key_text.setText("Click 'View Private Key' to display private key content")
                self.generate_button.setEnabled(True)
                self.renew_button.setEnabled(False)
                self._disable_key_buttons()
                return
            
            # Get the most recent key
            latest_key = keys
            
            # Check key status
            from datetime import datetime
            
            # Convert date strings from 'YYYY-MM-DD HH:MM:SS.ffffff' to 'YYYY-MM-DDTHH:MM:SS.ffffff' for fromisoformat
            created_at_str = latest_key['created_at'].replace(' ', 'T')
            expires_at_str = latest_key['expires_at'].replace(' ', 'T')

            created_at = datetime.fromisoformat(created_at_str)
            expires_at = datetime.fromisoformat(expires_at_str)
            now = datetime.now()
            days_until_expiry = (expires_at - now).days
            
            # Update status based on expiration
            if days_until_expiry < 0:
                status_text = f"🔴 Keys EXPIRED {abs(days_until_expiry)} days ago"
                status_color = "color: red; font-weight: bold;"
                key_status = "Expired"
            elif days_until_expiry <= 7:
                status_text = f"🟡 Keys expiring in {days_until_expiry} days"
                status_color = "color: orange; font-weight: bold;"
                key_status = "Near expiration"
            else:
                status_text = f"✅ Keys valid ({days_until_expiry} days remaining)"
                status_color = "color: green; font-weight: bold;"
                key_status = "Valid"
            
            self.status_label.setText(status_text)
            self.status_label.setStyleSheet(status_color)
            
            # Update key metadata with detailed information
            metadata = f"Key ID: {latest_key['id']}\n"
            metadata += f"Creation Date: {created_at.strftime('%Y-%m-%d %H:%M:%S')}\n"
            metadata += f"Expiration Date: {expires_at.strftime('%Y-%m-%d %H:%M:%S')}\n"
            metadata += f"Status: {key_status}\n"
            metadata += f"Algorithm: RSA-2048\n"
            metadata += f"Days Until Expiry: {days_until_expiry}"
            
            self.key_metadata.setText(metadata)
            
            # Display public key
            public_key_pem = latest_key['public_key']
            self.public_key_text.setText(public_key_pem)
            
            # Reset private key display
            self.private_key_text.setText("Click 'View Private Key' to display private key content")
            self.current_private_key = None
            
            # Enable key management buttons
            self.generate_button.setEnabled(True)
            self.renew_button.setEnabled(True)
            self._enable_key_buttons()
            
        except Exception as e:
            self.status_label.setText(f"Error loading key status: {str(e)}")
            self.status_label.setStyleSheet("color: red;")
            self._disable_key_buttons()
    
    def _enable_key_buttons(self):
        """Enable all key-related buttons"""
        self.save_public_pem_btn.setEnabled(True)
        self.copy_public_btn.setEnabled(True)
        self.view_private_btn.setEnabled(True)
        self.save_private_pem_btn.setEnabled(True)
        self.copy_private_btn.setEnabled(True)
    
    def _disable_key_buttons(self):
        """Disable all key-related buttons"""
        self.save_public_pem_btn.setEnabled(False)
        self.copy_public_btn.setEnabled(False)
        self.view_private_btn.setEnabled(False)
        self.save_private_pem_btn.setEnabled(False)
        self.copy_private_btn.setEnabled(False)
    
    def view_private_key(self):
        """View private key with password protection"""
        # Get passphrase
        password_dialog = PasswordDialog("View Private Key", "Enter your account passphrase:", self)
        if password_dialog.exec_() != password_dialog.Accepted:
            return
        
        passphrase = password_dialog.get_password()
        if not passphrase:
            show_error(self, "Error", "Passphrase is required.")
            return
        
        try:
            user_id = self.user_session.user_info['id']
            keys = self.db.get_user_keys_by_id(user_id)
            
            if not keys:
                show_error(self, "Error", "No keys found.")
                return
            
            # Decrypt private key
            encrypted_private_key = json.loads(keys['encrypted_private_key'])
            success, message, private_key = self.key_manager.decrypt_private_key(encrypted_private_key, passphrase)
            
            if success:
                # Convert private key to PEM format
                from cryptography.hazmat.primitives import serialization
                private_key_pem = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ).decode('utf-8')
                
                self.private_key_text.setText(private_key_pem)
                self.current_private_key = private_key_pem
                show_info(self, "Success", "Private key decrypted successfully.")
            else:
                show_error(self, "Decryption Failed", message)
                
        except Exception as e:
            show_error(self, "Error", f"Failed to decrypt private key: {str(e)}")
    
    def save_public_key_pem(self):
        """Save public key as .pem file"""
        try:
            user_id = self.user_session.user_info['id']
            keys = self.db.get_user_keys_by_id(user_id)
            
            if not keys:
                show_error(self, "Error", "No keys found.")
                return
            
            # Get save location
            filename, _ = QFileDialog.getSaveFileName(
                self,
                "Save Public Key",
                f"public_key_{user_id}.pem",
                "PEM Files (*.pem);;All Files (*)"
            )
            
            if filename:
                with open(filename, 'w') as f:
                    f.write(keys['public_key'])
                show_info(self, "Success", f"Public key saved to {filename}")
                
        except Exception as e:
            show_error(self, "Error", f"Failed to save public key: {str(e)}")
    
    def save_private_key_pem(self):
        """Save private key as .pem file"""
        if not self.current_private_key:
            show_error(self, "Error", "Please view the private key first.")
            return
        
        try:
            user_id = self.user_session.user_info['id']
            
            # Get save location
            filename, _ = QFileDialog.getSaveFileName(
                self,
                "Save Private Key",
                f"private_key_{user_id}.pem",
                "PEM Files (*.pem);;All Files (*)"
            )
            
            if filename:
                with open(filename, 'w') as f:
                    f.write(self.current_private_key)
                show_info(self, "Success", f"Private key saved to {filename}")
                
        except Exception as e:
            show_error(self, "Error", f"Failed to save private key: {str(e)}")
    
    def copy_public_key(self):
        """Copy public key to clipboard"""
        try:
            user_id = self.user_session.user_info['id']
            keys = self.db.get_user_keys_by_id(user_id)
            
            if not keys:
                show_error(self, "Error", "No keys found.")
                return
            
            from PyQt5.QtWidgets import QApplication
            clipboard = QApplication.clipboard()
            clipboard.setText(keys['public_key'])
            show_info(self, "Success", "Public key copied to clipboard.")
            
        except Exception as e:
            show_error(self, "Error", f"Failed to copy public key: {str(e)}")
    
    def copy_private_key(self):
        """Copy private key to clipboard"""
        if not self.current_private_key:
            show_error(self, "Error", "Please view the private key first.")
            return
        
        try:
            from PyQt5.QtWidgets import QApplication
            clipboard = QApplication.clipboard()
            clipboard.setText(self.current_private_key)
            show_info(self, "Success", "Private key copied to clipboard.")
            
        except Exception as e:
            show_error(self, "Error", f"Failed to copy private key: {str(e)}")
    
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