from PyQt5.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel, 
                             QLineEdit, QPushButton, QProgressBar, QTextEdit,
                             QMessageBox, QFileDialog, QGroupBox, QApplication)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont
import re

class PasswordDialog(QDialog):
    def __init__(self, title="Enter Password", prompt="Password:", parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setModal(True)
        self.setFixedSize(300, 120)
        
        layout = QVBoxLayout()
        
        # Prompt label
        prompt_label = QLabel(prompt)
        layout.addWidget(prompt_label)
        
        # Password input
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.returnPressed.connect(self.accept)
        layout.addWidget(self.password_input)
        
        # Buttons
        button_layout = QHBoxLayout()
        self.ok_button = QPushButton("OK")
        self.cancel_button = QPushButton("Cancel")
        
        self.ok_button.clicked.connect(self.accept)
        self.cancel_button.clicked.connect(self.reject)
        
        button_layout.addWidget(self.ok_button)
        button_layout.addWidget(self.cancel_button)
        
        layout.addLayout(button_layout)
        self.setLayout(layout)
        
        # Focus on password input
        self.password_input.setFocus()
    
    def get_password(self):
        return self.password_input.text()

class ProgressDialog(QDialog):
    def __init__(self, title="Processing", message="Please wait...", parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setModal(True)
        self.setFixedSize(400, 120)
        
        layout = QVBoxLayout()
        
        # Message label
        self.message_label = QLabel(message)
        layout.addWidget(self.message_label)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        layout.addWidget(self.progress_bar)
        
        # Cancel button
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.reject)
        layout.addWidget(self.cancel_button)
        
        self.setLayout(layout)
        
        self.is_cancelled = False
    
    def set_progress(self, value):
        self.progress_bar.setValue(value)
    
    def set_message(self, message):
        self.message_label.setText(message)
    
    def reject(self):
        self.is_cancelled = True
        super().reject()

class ConfirmDialog(QDialog):
    def __init__(self, title, message, parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setModal(True)
        self.setFixedSize(350, 120)
        
        layout = QVBoxLayout()
        
        # Message
        message_label = QLabel(message)
        message_label.setWordWrap(True)
        layout.addWidget(message_label)
        
        # Buttons
        button_layout = QHBoxLayout()
        self.yes_button = QPushButton("Yes")
        self.no_button = QPushButton("No")
        
        self.yes_button.clicked.connect(self.accept)
        self.no_button.clicked.connect(self.reject)
        
        button_layout.addWidget(self.yes_button)
        button_layout.addWidget(self.no_button)
        
        layout.addLayout(button_layout)
        self.setLayout(layout)

class InfoDialog(QDialog):
    def __init__(self, title, content, parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setModal(True)
        self.resize(500, 400)
        
        layout = QVBoxLayout()
        
        # Content text
        text_edit = QTextEdit()
        text_edit.setPlainText(content)
        text_edit.setReadOnly(True)
        text_edit.setFont(QFont("Courier", 9))
        layout.addWidget(text_edit)
        
        # Close button
        close_button = QPushButton("Close")
        close_button.clicked.connect(self.accept)
        layout.addWidget(close_button)
        
        self.setLayout(layout)

class RegistrationSuccessDialog(QDialog):
    def __init__(self, message, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Registration Successful")
        self.setModal(True)
        self.setFixedSize(600, 380)  # Increased from 480x280 to prevent cutoffs
        
        # Simple, clean styling
        self.setStyleSheet("""
            QDialog { 
                background-color: white; 
                border: 1px solid #ccc; 
            }
            QLabel { 
                color: #333; 
                padding: 3px;
            }
            QLineEdit { 
                background-color: #f9f9f9; 
                border: 1px solid #999; 
                padding: 10px; 
                border-radius: 3px;
                font-size: 12px;
            }
            QPushButton { 
                background-color: #f0f0f0; 
                border: 1px solid #999; 
                padding: 10px 20px; 
                border-radius: 3px;
                min-width: 100px;
                font-size: 11px;
            }
            QPushButton:hover { 
                background-color: #e8e8e8; 
            }
            QPushButton:pressed {
                background-color: #d8d8d8;
            }
        """)
        
        layout = QVBoxLayout()
        layout.setSpacing(15)  # Increased spacing
        layout.setContentsMargins(25, 25, 25, 25)  # Increased margins
        
        # Success message
        success_label = QLabel("✓ Account created successfully!")
        success_label.setStyleSheet("font-weight: bold; font-size: 16px; color: #2d5a27; padding: 8px;")
        layout.addWidget(success_label)
        
        # Extract recovery code from message
        recovery_code = self.extract_recovery_code(message)
        
        # Debug: print message and extracted code
        print(f"Message received: {message}")
        print(f"Extracted recovery code: {recovery_code}")
        
        if recovery_code:
            # Warning message - improved with proper sizing
            warning_label = QLabel("⚠ IMPORTANT: Save this recovery code securely.\nYou'll need it to recover your account if you forget your passphrase.")
            warning_label.setWordWrap(True)
            warning_label.setMinimumHeight(60)  # Ensure enough height
            warning_label.setStyleSheet("color: #d68910; font-weight: bold; font-size: 12px; padding: 8px; margin: 8px 0; background-color: #fef9e7; border: 1px solid #f1c40f; border-radius: 4px;")
            layout.addWidget(warning_label)
            
            # Recovery code display
            code_label = QLabel("Recovery Code:")
            code_label.setStyleSheet("font-weight: bold; color: #333; margin-top: 8px; font-size: 13px;")
            layout.addWidget(code_label)
            
            self.recovery_code_input = QLineEdit(recovery_code)
            self.recovery_code_input.setReadOnly(True)
            self.recovery_code_input.setFont(QFont("Courier", 12, QFont.Bold))
            self.recovery_code_input.setMinimumHeight(45)  # Increased height
            self.recovery_code_input.setStyleSheet("""
                background-color: #fff; 
                border: 2px solid #007acc; 
                padding: 12px; 
                font-weight: bold; 
                color: #000;
                text-align: center;
                font-size: 13px;
            """)
            self.recovery_code_input.setAlignment(Qt.AlignCenter)
            self.recovery_code_input.selectAll()
            layout.addWidget(self.recovery_code_input)
            
            # Buttons - improved layout
            button_layout = QHBoxLayout()
            button_layout.setSpacing(15)
            
            copy_button = QPushButton("Copy")
            copy_button.clicked.connect(self.copy_recovery_code)
            copy_button.setStyleSheet("background-color: #007acc; color: white; font-weight: bold; font-size: 12px;")
            
            save_button = QPushButton("Save to File")
            save_button.clicked.connect(self.save_recovery_code)
            save_button.setStyleSheet("font-size: 12px;")
            
            button_layout.addWidget(copy_button)
            button_layout.addWidget(save_button)
            layout.addLayout(button_layout)
        else:
            # Fallback: show full message if code extraction fails
            full_message_label = QLabel(message)
            full_message_label.setWordWrap(True)
            full_message_label.setMinimumHeight(80)  # Ensure enough space
            full_message_label.setStyleSheet("color: #333; font-size: 12px; padding: 8px; margin: 8px 0; background-color: #f8f9fa; border: 1px solid #dee2e6; border-radius: 4px;")
            layout.addWidget(full_message_label)
        
        # RSA keys info
        if "RSA keys generated" in message:
            keys_label = QLabel("🔑 RSA keys generated and ready for use.")
            keys_label.setStyleSheet("color: #2d5a27; font-size: 12px; font-style: italic; padding: 8px;")
            layout.addWidget(keys_label)
        
        # Add some stretch space before the OK button
        layout.addStretch()
        
        # Close button
        ok_button = QPushButton("OK")
        ok_button.clicked.connect(self.accept)
        ok_button.setDefault(True)
        ok_button.setStyleSheet("""
            background-color: #28a745; 
            color: white; 
            font-weight: bold; 
            padding: 12px 30px; 
            margin-top: 15px;
            font-size: 13px;
        """)
        layout.addWidget(ok_button)
        
        self.setLayout(layout)
        
        # Focus on the recovery code for easy copying
        if hasattr(self, 'recovery_code_input'):
            self.recovery_code_input.setFocus()
    
    def extract_recovery_code(self, message):
        """Extract recovery code from the message string"""
        print(f"Attempting to extract recovery code from: '{message}'")
        
        # More specific patterns to find the recovery code
        patterns = [
            r'recovery code:\s*([A-Z0-9]{12,20})',    # Pattern with length constraint
            r'code:\s*([A-Z0-9]{12,20})',            # Shorter pattern with length
            r'\b([A-Z0-9]{16})\b',                    # Exact 16-character code
            r'\b([A-Z0-9]{12,20})\b'                  # 12-20 character alphanumeric
        ]
        
        for i, pattern in enumerate(patterns):
            matches = re.findall(pattern, message, re.IGNORECASE)
            print(f"Pattern {i+1} '{pattern}' found matches: {matches}")
            
            for match in matches:
                code = match.upper()
                # Validate it's not a common word and looks like a recovery code
                if (len(code) >= 12 and 
                    re.match(r'^[A-Z0-9]+$', code) and 
                    code not in ['REGISTRATION', 'SUCCESSFUL', 'GENERATED', 'READY']):
                    print(f"Valid recovery code found: {code}")
                    return code
        
        print("No valid recovery code found")
        return None
    
    def copy_recovery_code(self):
        """Copy recovery code to clipboard"""
        if hasattr(self, 'recovery_code_input'):
            clipboard = QApplication.clipboard()
            clipboard.setText(self.recovery_code_input.text())
            
            # Show brief confirmation
            original_text = self.sender().text()
            self.sender().setText("Copied!")
            
            # Reset button text after 1.5 seconds
            from PyQt5.QtCore import QTimer
            button = self.sender()
            QTimer.singleShot(1500, lambda: self.reset_button_text(button, original_text))
    
    def save_recovery_code(self):
        """Save recovery code to a text file"""
        if hasattr(self, 'recovery_code_input'):
            from PyQt5.QtWidgets import QFileDialog
            
            filename, _ = QFileDialog.getSaveFileName(
                self, 
                "Save Recovery Code", 
                "recovery_code.txt", 
                "Text Files (*.txt);;All Files (*)"
            )
            
            if filename:
                try:
                    with open(filename, 'w') as f:
                        f.write(f"Security Application - Recovery Code\n")
                        f.write(f"Generated: {self.get_current_datetime()}\n")
                        f.write(f"Recovery Code: {self.recovery_code_input.text()}\n\n")
                        f.write("IMPORTANT: Keep this code secure and do not share it.\n")
                        f.write("You will need this code to recover your account if you forget your passphrase.\n")
                    
                    # Show confirmation
                    original_text = self.sender().text()
                    self.sender().setText("Saved!")
                    
                    from PyQt5.QtCore import QTimer
                    button = self.sender()
                    QTimer.singleShot(1500, lambda: self.reset_button_text(button, original_text))
                    
                except Exception as e:
                    from PyQt5.QtWidgets import QMessageBox
                    QMessageBox.critical(self, "Save Error", f"Failed to save file: {str(e)}")
    
    def get_current_datetime(self):
        """Get current datetime as formatted string"""
        from datetime import datetime
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    def reset_button_text(self, button, original_text):
        """Safely reset button text, checking if button still exists"""
        try:
            # Check if button object still exists and hasn't been deleted
            if button and not button.isHidden() and button.parent():
                button.setText(original_text)
        except RuntimeError:
            # Button has been deleted, ignore silently
            pass

def show_error(parent, title, message):
    QMessageBox.critical(parent, title, message)

def show_warning(parent, title, message):
    QMessageBox.warning(parent, title, message)

def show_info(parent, title, message):
    QMessageBox.information(parent, title, message)

def show_question(parent, title, message):
    reply = QMessageBox.question(parent, title, message, 
                                QMessageBox.Yes | QMessageBox.No)
    return reply == QMessageBox.Yes

def get_open_file(parent, title, filter_str="All Files (*)"):
    filename, _ = QFileDialog.getOpenFileName(parent, title, "", filter_str)
    return filename

def get_save_file(parent, title, filter_str="All Files (*)"):
    filename, _ = QFileDialog.getSaveFileName(parent, title, "", filter_str)
    return filename 