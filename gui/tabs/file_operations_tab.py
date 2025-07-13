from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, 
                             QPushButton, QLabel, QComboBox, QLineEdit,
                             QProgressBar, QTextEdit, QFormLayout)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont
from ..utils.dialogs import (show_error, show_info, show_warning, show_question, 
                            get_open_file, get_save_file, PasswordDialog)

class FileOperationWorker(QThread):
    progress_updated = pyqtSignal(str, int)
    operation_completed = pyqtSignal(bool, str)
    
    def __init__(self, operation, file_crypto, **kwargs):
        super().__init__()
        self.operation = operation
        self.file_crypto = file_crypto
        self.kwargs = kwargs
    
    def run(self):
        try:
            if self.operation == 'encrypt':
                success, message, _ = self.file_crypto.encrypt_file(
                    **self.kwargs
                )
            elif self.operation == 'decrypt':
                success, message, _ = self.file_crypto.decrypt_file(
                    **self.kwargs
                )
            else:
                success, message = False, "Unknown operation"
            
            self.operation_completed.emit(success, message)
            
        except Exception as e:
            self.operation_completed.emit(False, str(e))

class FileOperationsTab(QWidget):
    def __init__(self, user_session, managers, parent=None):
        super().__init__(parent)
        self.user_session = user_session
        self.managers = managers
        self.file_crypto = managers['file_crypto']
        self.db = managers['db']
        self.worker = None
        self.setup_ui()
        self.refresh_recipients()
    
    def setup_ui(self):
        layout = QVBoxLayout()
        
        # File Encryption Section
        encrypt_group = QGroupBox("Encrypt File")
        encrypt_layout = QFormLayout()
        
        # File selection
        file_select_layout = QHBoxLayout()
        self.encrypt_file_input = QLineEdit()
        self.encrypt_file_input.setPlaceholderText("Select file to encrypt...")
        self.encrypt_file_input.setReadOnly(True)
        file_select_layout.addWidget(self.encrypt_file_input)
        
        self.select_file_button = QPushButton("Browse")
        self.select_file_button.clicked.connect(self.select_file_to_encrypt)
        file_select_layout.addWidget(self.select_file_button)
        
        encrypt_layout.addRow("File:", file_select_layout)
        
        # Recipient selection
        self.recipient_combo = QComboBox()
        self.recipient_combo.setEditable(False)
        encrypt_layout.addRow("Recipient:", self.recipient_combo)
        
        # Refresh recipients button
        refresh_layout = QHBoxLayout()
        self.refresh_recipients_button = QPushButton("Refresh Recipients")
        self.refresh_recipients_button.clicked.connect(self.refresh_recipients)
        refresh_layout.addWidget(self.refresh_recipients_button)
        refresh_layout.addStretch()
        
        encrypt_layout.addRow("", refresh_layout)
        
        # Output Format selection for Feature 16
        self.output_format_combo = QComboBox()
        self.output_format_combo.addItem("Combined (.enc)", "combined")
        self.output_format_combo.addItem("Separate (.enc + .key)", "separate")
        encrypt_layout.addRow("Output Format:", self.output_format_combo)

        # Encrypt button
        self.encrypt_button = QPushButton("Encrypt File")
        self.encrypt_button.clicked.connect(self.encrypt_file)
        encrypt_layout.addRow("", self.encrypt_button)
        
        encrypt_group.setLayout(encrypt_layout)
        layout.addWidget(encrypt_group)
        
        # File Decryption Section
        decrypt_group = QGroupBox("Decrypt File")
        decrypt_layout = QFormLayout()
        
        # Encrypted file selection
        decrypt_file_select_layout = QHBoxLayout()
        self.decrypt_file_input = QLineEdit()
        self.decrypt_file_input.setPlaceholderText("Select encrypted file...")
        self.decrypt_file_input.setReadOnly(True)
        decrypt_file_select_layout.addWidget(self.decrypt_file_input)
        
        self.select_decrypt_file_button = QPushButton("Browse")
        self.select_decrypt_file_button.clicked.connect(self.select_file_to_decrypt)
        decrypt_file_select_layout.addWidget(self.select_decrypt_file_button)
        
        decrypt_layout.addRow("Encrypted File:", decrypt_file_select_layout)
        
        # Decrypt button
        self.decrypt_button = QPushButton("Decrypt File")
        self.decrypt_button.clicked.connect(self.decrypt_file)
        decrypt_layout.addRow("", self.decrypt_button)
        
        decrypt_group.setLayout(decrypt_layout)
        layout.addWidget(decrypt_group)
        
        # Progress Section
        self.progress_group = QGroupBox("Operation Progress")
        progress_layout = QVBoxLayout()
        
        self.progress_label = QLabel("")
        progress_layout.addWidget(self.progress_label)
        
        self.progress_bar = QProgressBar()
        progress_layout.addWidget(self.progress_bar)
        
        self.cancel_button = QPushButton("Cancel Operation")
        self.cancel_button.clicked.connect(self.cancel_operation)
        progress_layout.addWidget(self.cancel_button)
        
        self.progress_group.setLayout(progress_layout)
        self.progress_group.hide()
        layout.addWidget(self.progress_group)
        
        # Info Section
        info_group = QGroupBox("File Operation Information")
        info_layout = QVBoxLayout()
        
        info_text = QLabel("""File Encryption Information:
• Files are encrypted using AES-256-GCM for security
• RSA public keys encrypt the AES session keys
• Large files (>5MB) are processed in chunks for efficiency
• Encrypted files can be saved in combined (.enc) or separate (.enc + .key) format
• Only the recipient's private key can decrypt the file""")
        info_text.setWordWrap(True)
        info_text.setStyleSheet("color: #666; font-style: italic;")
        info_layout.addWidget(info_text)
        
        info_group.setLayout(info_layout)
        layout.addWidget(info_group)
        
        layout.addStretch()
        self.setLayout(layout)
    
    def select_file_to_encrypt(self):
        """Select file to encrypt"""
        filename = get_open_file(self, "Select File to Encrypt", "All Files (*)")
        if filename:
            self.encrypt_file_input.setText(filename)
    
    def select_file_to_decrypt(self):
        """Select encrypted file to decrypt"""
        filename = get_open_file(self, "Select Encrypted File", 
                                "Encrypted Files (*.enc);;All Files (*)")
        if filename:
            self.decrypt_file_input.setText(filename)
    
    def refresh_recipients(self):
        """Refresh the recipients list"""
        try:
            # Get all imported public keys
            public_keys = self.db.get_public_keys_by_user(self.user_session.user_info['id'])
            
            self.recipient_combo.clear()
            
            if not public_keys:
                self.recipient_combo.addItem("No recipients available - Import public keys first")
                self.encrypt_button.setEnabled(False)
                return
            
            # Add recipients to combo box
            for key in public_keys:
                if key['is_active']:
                    display_text = f"{key['owner_email']} (Imported: {key['imported_at'].split('T')[0]})"
                    self.recipient_combo.addItem(display_text, key['owner_email'])
            
            self.encrypt_button.setEnabled(self.recipient_combo.count() > 0)
            
        except Exception as e:
            show_error(self, "Error", f"Failed to refresh recipients: {str(e)}")
    
    def encrypt_file(self):
        """Encrypt the selected file"""
        input_file = self.encrypt_file_input.text().strip()
        if not input_file:
            show_warning(self, "No File Selected", "Please select a file to encrypt.")
            return
        
        if self.recipient_combo.count() == 0:
            show_warning(self, "No Recipients", "No recipients available. Please import public keys first.")
            return
        
        # Get recipient email
        recipient_email = self.recipient_combo.currentData()
        if not recipient_email:
            show_warning(self, "No Recipient", "Please select a recipient.")
            return
        
        # Get output location
        output_file = get_save_file(self, "Save Encrypted File", "Encrypted Files (*.enc)")
        if not output_file:
            return
        
        if not output_file.lower().endswith('.enc'):
            output_file += '.enc'
        
        # Confirm operation
        if not show_question(self, "Encrypt File", 
                           f"Encrypt '{input_file}' for {recipient_email}?"):
            return
        
        # Start encryption in background thread
        self.show_progress("Preparing to encrypt file...", 0)
        
        self.worker = FileOperationWorker(
            'encrypt', self.file_crypto,
            file_path=input_file, # Changed input_file to file_path
            recipient_email=recipient_email,
            sender_user_id=self.user_session.user_info['id'], # Changed sender_email to sender_user_id
            output_format=self.output_format_combo.currentData() # Added output_format
            # The output_file parameter is handled by file_crypto.encrypt_file internally.
        )
        self.worker.progress_updated.connect(self.update_progress)
        self.worker.operation_completed.connect(self.encryption_completed)
        self.worker.start()
    
    def decrypt_file(self):
        """Decrypt the selected file"""
        input_file = self.decrypt_file_input.text().strip()
        if not input_file:
            show_warning(self, "No File Selected", "Please select an encrypted file to decrypt.")
            return
        
        # Auto-generate output filename - this is now handled internally by decrypt_file
        # if input_file.lower().endswith('.enc'):
        #     suggested_output = input_file[:-4]  # Remove .enc extension
        # else:
        #     suggested_output = input_file + '_decrypted'
        
        # Get output location (no longer directly passed to worker, handled by file_crypto)
        # output_file = get_save_file(self, "Save Decrypted File", "All Files (*)")
        # if not output_file:
        #     return
        
        # Prompt for passphrase for decryption
        password_dialog = PasswordDialog("Decrypt File", "Enter your account passphrase:", self)
        if password_dialog.exec_() != password_dialog.Accepted:
            return
        
        passphrase = password_dialog.get_password()
        if not passphrase:
            show_error(self, "Error", "Passphrase is required.")
            return

        # Confirm operation
        if not show_question(self, "Decrypt File", 
                           f"Decrypt '{input_file}'?"):
            return
        
        # Start decryption in background thread
        self.show_progress("Preparing to decrypt file...", 0)
        
        self.worker = FileOperationWorker(
            'decrypt', self.file_crypto,
            encrypted_file_path=input_file, # Use correct parameter name
            user_id=self.user_session.user_info['id'],
            passphrase=passphrase,
            key_file_path=None # Assuming combined format for now, or add UI for separate
        )
        self.worker.progress_updated.connect(self.update_progress)
        self.worker.operation_completed.connect(self.decryption_completed)
        self.worker.start()
    
    def show_progress(self, message, value):
        """Show progress bar"""
        self.progress_label.setText(message)
        self.progress_bar.setValue(value)
        self.progress_group.show()
        
        # Disable operation buttons
        self.encrypt_button.setEnabled(False)
        self.decrypt_button.setEnabled(False)
    
    def hide_progress(self):
        """Hide progress bar"""
        self.progress_group.hide()
        
        # Re-enable operation buttons
        self.encrypt_button.setEnabled(self.recipient_combo.count() > 0)
        self.decrypt_button.setEnabled(True)
    
    def update_progress(self, message, value):
        """Update progress display"""
        self.progress_label.setText(message)
        self.progress_bar.setValue(value)
    
    def encryption_completed(self, success, message):
        """Handle encryption completion"""
        self.hide_progress()
        
        if success:
            show_info(self, "Encryption Successful", message)
            # Clear inputs
            self.encrypt_file_input.clear()
        else:
            show_error(self, "Encryption Failed", message)
    
    def decryption_completed(self, success, message):
        """Handle decryption completion"""
        self.hide_progress()
        
        if success:
            show_info(self, "Decryption Successful", message)
            # Clear inputs
            self.decrypt_file_input.clear()
        else:
            show_error(self, "Decryption Failed", message)
    
    def cancel_operation(self):
        """Cancel the current operation"""
        if self.worker and self.worker.isRunning():
            self.worker.terminate()
            self.worker.wait()
            self.hide_progress()
            show_info(self, "Operation Cancelled", "File operation was cancelled.")
    
    def refresh_data(self):
        """Refresh tab data"""
        self.refresh_recipients() 