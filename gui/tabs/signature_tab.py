from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, 
                             QPushButton, QLabel, QLineEdit, QFormLayout,
                             QTextEdit, QInputDialog)
from PyQt5.QtCore import Qt
from ..utils.dialogs import (show_error, show_info, show_warning, show_question, 
                            get_open_file, get_save_file)

class SignatureTab(QWidget):
    def __init__(self, user_session, managers, parent=None):
        super().__init__(parent)
        self.user_session = user_session
        self.managers = managers
        self.digital_signature = managers['digital_signature']
        self.signature_verification = managers['signature_verification']
        self.setup_ui()
    
    def setup_ui(self):
        layout = QVBoxLayout()
        
        # File Signing Section
        sign_group = QGroupBox("Sign File")
        sign_layout = QFormLayout()
        
        # File selection for signing
        sign_file_layout = QHBoxLayout()
        self.sign_file_input = QLineEdit()
        self.sign_file_input.setPlaceholderText("Select file to sign...")
        self.sign_file_input.setReadOnly(True)
        sign_file_layout.addWidget(self.sign_file_input)
        
        self.select_sign_file_button = QPushButton("Browse")
        self.select_sign_file_button.clicked.connect(self.select_file_to_sign)
        sign_file_layout.addWidget(self.select_sign_file_button)
        
        sign_layout.addRow("File to Sign:", sign_file_layout)
        
        # Sign button
        self.sign_button = QPushButton("Create Digital Signature")
        self.sign_button.clicked.connect(self.sign_file)
        sign_layout.addRow("", self.sign_button)
        
        sign_group.setLayout(sign_layout)
        layout.addWidget(sign_group)
        
        # Signature Verification Section
        verify_group = QGroupBox("Verify Signature")
        verify_layout = QFormLayout()
        
        # File selection for verification
        verify_file_layout = QHBoxLayout()
        self.verify_file_input = QLineEdit()
        self.verify_file_input.setPlaceholderText("Select file to verify...")
        self.verify_file_input.setReadOnly(True)
        verify_file_layout.addWidget(self.verify_file_input)
        
        self.select_verify_file_button = QPushButton("Browse")
        self.select_verify_file_button.clicked.connect(self.select_file_to_verify)
        verify_file_layout.addWidget(self.select_verify_file_button)
        
        verify_layout.addRow("Original File:", verify_file_layout)
        
        # Signature file selection
        sig_file_layout = QHBoxLayout()
        self.sig_file_input = QLineEdit()
        self.sig_file_input.setPlaceholderText("Select signature file...")
        self.sig_file_input.setReadOnly(True)
        sig_file_layout.addWidget(self.sig_file_input)
        
        self.select_sig_file_button = QPushButton("Browse")
        self.select_sig_file_button.clicked.connect(self.select_signature_file)
        sig_file_layout.addWidget(self.select_sig_file_button)
        
        verify_layout.addRow("Signature File (.sig):", sig_file_layout)
        
        # Verify button
        self.verify_button = QPushButton("Verify Signature")
        self.verify_button.clicked.connect(self.verify_signature)
        verify_layout.addRow("", self.verify_button)
        
        verify_group.setLayout(verify_layout)
        layout.addWidget(verify_group)
        
        # Results Section
        results_group = QGroupBox("Verification Results")
        results_layout = QVBoxLayout()
        
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        self.results_text.setMaximumHeight(150)
        self.results_text.setPlaceholderText("Verification results will appear here...")
        results_layout.addWidget(self.results_text)
        
        results_group.setLayout(results_layout)
        layout.addWidget(results_group)

        layout.addStretch()
        self.setLayout(layout)
    
    def select_file_to_sign(self):
        """Select file to sign"""
        filename = get_open_file(self, "Select File to Sign", "All Files (*)")
        if filename:
            self.sign_file_input.setText(filename)
    
    def select_file_to_verify(self):
        """Select file to verify"""
        filename = get_open_file(self, "Select File to Verify", "All Files (*)")
        if filename:
            self.verify_file_input.setText(filename)
    
    def select_signature_file(self):
        """Select signature file"""
        filename = get_open_file(self, "Select Signature File", "Signature Files (*.sig);;All Files (*)")
        if filename:
            self.sig_file_input.setText(filename)
    
    def sign_file(self):
        """Create digital signature for file"""
        input_file = self.sign_file_input.text().strip()
        if not input_file:
            show_warning(self, "No File Selected", "Please select a file to sign.")
            return
        
        # Get signature file location
        suggested_sig_file = input_file + '.sig'
        sig_file = get_save_file(self, "Save Signature File", "Signature Files (*.sig)")
        if not sig_file:
            return
        
        if not sig_file.lower().endswith('.sig'):
            sig_file += '.sig'
        
        try:
            # Prompt for passphrase
            passphrase, ok = QInputDialog.getText(
                self, 
                "Enter Passphrase", 
                "Enter your private key passphrase:", 
                QLineEdit.Password
            )
            
            if not ok or not passphrase:
                show_warning(self, "Signing Cancelled", "Passphrase is required for signing.")
                return
                
            # Create digital signature
            success, message = self.digital_signature.sign_file(
                input_file, passphrase
            )
            
            if success:
                # The signature is created with default naming, so we need to move it
                import os
                default_sig_file = input_file + '.sig'
                if os.path.exists(default_sig_file) and sig_file != default_sig_file:
                    import shutil
                    shutil.move(default_sig_file, sig_file)
                
                show_info(self, "Signature Created", 
                         f"Digital signature created successfully:\n{sig_file}")
                self.sign_file_input.clear()
            else:
                show_error(self, "Signing Failed", message)
                
        except Exception as e:
            show_error(self, "Error", f"Failed to create signature: {str(e)}")
    
    def verify_signature(self):
        """Verify digital signature"""
        original_file = self.verify_file_input.text().strip()
        signature_file = self.sig_file_input.text().strip()
        
        if not original_file:
            show_warning(self, "No File Selected", "Please select the original file to verify.")
            return
        
        if not signature_file:
            show_warning(self, "No Signature File", "Please select the signature file (.sig).")
            return
        
        try:
            print(f"DEBUG: Verifying file: {original_file}")
            print(f"DEBUG: With signature: {signature_file}")
            
            # Verify signature
            success, message = self.signature_verification.verify_signature(
                original_file, signature_file
            )
            
            # Display results
            self.results_text.clear()
            
            if success:
                self.results_text.setStyleSheet("color: green;")
                self.results_text.setText(f"✓ VERIFICATION SUCCESSFUL\n\n{message}")
                
                # Parse signature file to extract metadata for display
                try:
                    import json
                    with open(signature_file, 'rb') as f:
                        content = f.read()
                    
                    if b"---SIGNATURE---" in content:
                        metadata_json = content.split(b"---SIGNATURE---", 1)[0].decode('utf-8')
                        metadata = json.loads(metadata_json)
                        
                        # Add metadata details to results
                        self.results_text.append("\n\nSignature Details:")
                        self.results_text.append(f"• Signer: {metadata.get('signer_email', 'Unknown')}")
                        self.results_text.append(f"• Date: {metadata.get('timestamp', 'Unknown')}")
                        self.results_text.append(f"• File: {metadata.get('original_filename', 'Unknown')}")
                        self.results_text.append(f"• Hash: {metadata.get('file_hash', 'Unknown')}")
                except Exception as e:
                    # If metadata parsing fails, just show the success message
                    print(f"DEBUG: Error parsing metadata: {e}")
            else:
                self.results_text.setStyleSheet("color: red;")
                self.results_text.setText(f"❌ VERIFICATION ERROR\n\n{message}")
            
        except Exception as e:
            print(f"DEBUG: Exception in verify_signature UI method: {type(e).__name__}: {str(e)}")
            self.results_text.setStyleSheet("color: red;")
            self.results_text.setText(f"❌ VERIFICATION ERROR\n\nFailed to verify signature: {str(e)}")
    
    def refresh_data(self):
        """Refresh tab data"""
        pass  # No data to refresh for signature tab 