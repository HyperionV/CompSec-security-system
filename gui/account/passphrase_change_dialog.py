from PyQt5.QtWidgets import (QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, 
                             QPushButton, QFrame, QProgressBar, QGroupBox,
                             QFormLayout, QSpacerItem, QSizePolicy)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QThread, pyqtSlot
from PyQt5.QtGui import QFont
from ..base.base_dialog import BaseDialog
from ..utils.message_boxes import MessageBoxes
from modules.auth import AuthManager

class PassphraseChangeWorker(QThread):
    """Worker thread for passphrase change operations"""
    
    finished = pyqtSignal(bool, str)
    progress = pyqtSignal(str)
    
    def __init__(self, user_id, current_password, new_password):
        super().__init__()
        self.user_id = user_id
        self.current_password = current_password
        self.new_password = new_password
        
    def run(self):
        """Execute passphrase change operation"""
        try:
            self.progress.emit("Validating current passphrase...")
            auth_manager = AuthManager()
            
            self.progress.emit("Changing passphrase and re-encrypting keys...")
            success, message = auth_manager.change_passphrase(
                self.user_id, self.current_password, self.new_password
            )
            
            if success:
                self.progress.emit("Passphrase changed successfully!")
            
            self.finished.emit(success, message)
            
        except Exception as e:
            self.finished.emit(False, f"Passphrase change failed: {str(e)}")

class PassphraseChangeDialog(BaseDialog):
    """
    Dialog for changing user passphrase with key re-encryption
    
    This dialog handles:
    - Current passphrase verification
    - New passphrase strength validation
    - Private key re-encryption process
    - Progress indication and error handling
    """
    
    passphrase_changed = pyqtSignal()
    
    def __init__(self, session_manager, parent=None):
        self.session_manager = session_manager
        self.change_worker = None
        
        super().__init__("Change Passphrase", parent)
        self.setup_ui()
        self.setup_connections()
        
    def setup_ui(self):
        """Setup the passphrase change dialog UI"""
        self.setFixedSize(500, 400)
        
        # Add title
        self.add_title_label(
            "Change Account Passphrase",
            "Change your passphrase. All RSA keys will be re-encrypted with the new passphrase."
        )
        
        # Current passphrase section
        current_group = QGroupBox("Current Passphrase")
        current_layout = QFormLayout(current_group)
        
        self.current_passphrase_input = QLineEdit()
        self.current_passphrase_input.setEchoMode(QLineEdit.Password)
        self.current_passphrase_input.setPlaceholderText("Enter your current passphrase")
        
        current_layout.addRow("Current Passphrase:", self.current_passphrase_input)
        self.add_content_widget(current_group)
        
        # New passphrase section
        new_group = QGroupBox("New Passphrase")
        new_layout = QFormLayout(new_group)
        
        self.new_passphrase_input = QLineEdit()
        self.new_passphrase_input.setEchoMode(QLineEdit.Password)
        self.new_passphrase_input.setPlaceholderText("Enter new passphrase")
        self.new_passphrase_input.textChanged.connect(self.validate_new_passphrase)
        
        self.confirm_passphrase_input = QLineEdit()
        self.confirm_passphrase_input.setEchoMode(QLineEdit.Password)
        self.confirm_passphrase_input.setPlaceholderText("Confirm new passphrase")
        self.confirm_passphrase_input.textChanged.connect(self.validate_passphrase_match)
        
        new_layout.addRow("New Passphrase:", self.new_passphrase_input)
        new_layout.addRow("Confirm New:", self.confirm_passphrase_input)
        
        # Passphrase strength indicator
        self.strength_label = QLabel("Enter a passphrase to see strength")
        self.strength_label.setStyleSheet("color: #6c757d; font-style: italic;")
        new_layout.addWidget(self.strength_label)
        
        # Passphrase match indicator
        self.match_label = QLabel("")
        new_layout.addWidget(self.match_label)
        
        self.add_content_widget(new_group)
        
        # Progress section
        progress_group = QGroupBox("Operation Progress")
        progress_layout = QVBoxLayout(progress_group)
        
        self.progress_label = QLabel("Ready to change passphrase")
        self.progress_label.setAlignment(Qt.AlignCenter)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        
        progress_layout.addWidget(self.progress_label)
        progress_layout.addWidget(self.progress_bar)
        
        self.add_content_widget(progress_group)
        
        # Warning section
        warning_frame = QFrame()
        warning_layout = QVBoxLayout(warning_frame)
        
        warning_label = QLabel("⚠️ Important Notes:")
        warning_label.setFont(QFont("Arial", 9, QFont.Bold))
        warning_label.setStyleSheet("color: #856404;")
        
        warning_text = QLabel(
            "• This operation will re-encrypt all your RSA private keys\n"
            "• The process may take a few moments to complete\n"
            "• Do not close the dialog while the operation is running"
        )
        warning_text.setStyleSheet("color: #856404; background-color: #fff3cd; padding: 8px; border-radius: 3px;")
        warning_text.setWordWrap(True)
        
        warning_layout.addWidget(warning_label)
        warning_layout.addWidget(warning_text)
        
        self.add_content_widget(warning_frame)
        
        # Add buttons
        self.add_standard_buttons()
        self.set_ok_button_text("Change Passphrase")
        
        # Initially disable OK button
        ok_button = self.button_box.button(self.button_box.Ok)
        ok_button.setEnabled(False)
        
    def setup_connections(self):
        """Setup signal connections"""
        super().setup_connections()
        
        # Override OK button to perform passphrase change
        ok_button = self.button_box.button(self.button_box.Ok)
        ok_button.clicked.disconnect()  # Disconnect default accept
        ok_button.clicked.connect(self.change_passphrase)
        
        # Input validation
        self.current_passphrase_input.textChanged.connect(self.validate_form)
        self.new_passphrase_input.textChanged.connect(self.validate_form)
        self.confirm_passphrase_input.textChanged.connect(self.validate_form)
        
    def validate_new_passphrase(self):
        """Validate new passphrase strength"""
        passphrase = self.new_passphrase_input.text()
        
        if not passphrase:
            self.strength_label.setText("Enter a passphrase to see strength")
            self.strength_label.setStyleSheet("color: #6c757d; font-style: italic;")
            return False
        
        # Check length
        if len(passphrase) < 8:
            self.strength_label.setText("⚠️ Too short (minimum 8 characters)")
            self.strength_label.setStyleSheet("color: #dc3545;")
            return False
            
        # Check complexity
        has_upper = any(c.isupper() for c in passphrase)
        has_lower = any(c.islower() for c in passphrase)
        has_digit = any(c.isdigit() for c in passphrase)
        has_special = any(c in "!@#$%^&*(),.?\":{}|<>" for c in passphrase)
        
        score = sum([has_upper, has_lower, has_digit, has_special])
        
        if score < 3:
            self.strength_label.setText("⚠️ Weak (needs uppercase, lowercase, number, and special character)")
            self.strength_label.setStyleSheet("color: #dc3545;")
            return False
        elif score == 3:
            self.strength_label.setText("✓ Good passphrase strength")
            self.strength_label.setStyleSheet("color: #ffc107;")
            return True
        else:
            self.strength_label.setText("✓ Strong passphrase")
            self.strength_label.setStyleSheet("color: #28a745;")
            return True
    
    def validate_passphrase_match(self):
        """Validate passphrase confirmation match"""
        new_passphrase = self.new_passphrase_input.text()
        confirm_passphrase = self.confirm_passphrase_input.text()
        
        if not confirm_passphrase:
            self.match_label.setText("")
            return False
            
        if new_passphrase == confirm_passphrase:
            self.match_label.setText("✓ Passphrases match")
            self.match_label.setStyleSheet("color: #28a745;")
            return True
        else:
            self.match_label.setText("⚠️ Passphrases do not match")
            self.match_label.setStyleSheet("color: #dc3545;")
            return False
    
    def validate_form(self):
        """Validate entire form and enable/disable OK button"""
        current_valid = len(self.current_passphrase_input.text()) > 0
        new_valid = self.validate_new_passphrase()
        match_valid = self.validate_passphrase_match()
        
        ok_button = self.button_box.button(self.button_box.Ok)
        ok_button.setEnabled(current_valid and new_valid and match_valid)
    
    def change_passphrase(self):
        """Initiate passphrase change operation"""
        if not self.session_manager.is_authenticated():
            MessageBoxes.show_error(self, "Error", "Not authenticated")
            return
            
        current_passphrase = self.current_passphrase_input.text()
        new_passphrase = self.new_passphrase_input.text()
        
        if not current_passphrase or not new_passphrase:
            MessageBoxes.show_error(self, "Validation Error", "All fields are required")
            return
            
        if new_passphrase == current_passphrase:
            MessageBoxes.show_error(self, "Validation Error", "New passphrase must be different from current")
            return
            
        # Confirm the operation
        reply = MessageBoxes.show_question(
            self, 
            "Confirm Passphrase Change", 
            "This will change your passphrase and re-encrypt all RSA keys.\n\nContinue?"
        )
        
        if reply != MessageBoxes.Yes:
            return
            
        # Disable form and start operation
        self.set_form_enabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate progress
        
        user_id = self.session_manager.get_user_id()
        
        self.change_worker = PassphraseChangeWorker(user_id, current_passphrase, new_passphrase)
        self.change_worker.finished.connect(self.on_change_finished)
        self.change_worker.progress.connect(self.on_progress_update)
        self.change_worker.start()
    
    def set_form_enabled(self, enabled):
        """Enable/disable form inputs"""
        self.current_passphrase_input.setEnabled(enabled)
        self.new_passphrase_input.setEnabled(enabled)
        self.confirm_passphrase_input.setEnabled(enabled)
        
        ok_button = self.button_box.button(self.button_box.Ok)
        cancel_button = self.button_box.button(self.button_box.Cancel)
        
        if enabled:
            self.validate_form()  # Re-validate to set OK button state
        else:
            ok_button.setEnabled(False)
            
        cancel_button.setEnabled(enabled)
    
    @pyqtSlot(str)
    def on_progress_update(self, message):
        """Handle progress updates"""
        self.progress_label.setText(message)
    
    @pyqtSlot(bool, str)
    def on_change_finished(self, success, message):
        """Handle passphrase change completion"""
        self.progress_bar.setVisible(False)
        self.set_form_enabled(True)
        
        if success:
            MessageBoxes.show_info(self, "Success", "Passphrase changed successfully!\n\nAll RSA keys have been re-encrypted.")
            self.progress_label.setText("Passphrase changed successfully")
            self.passphrase_changed.emit()
            
            # Auto-close after success
            QTimer.singleShot(1000, self.accept)
            
        else:
            MessageBoxes.show_error(self, "Passphrase Change Failed", message)
            self.progress_label.setText("Ready to change passphrase")
            
            # Clear current passphrase field on failure
            self.current_passphrase_input.clear()
            self.current_passphrase_input.setFocus()
    
    def closeEvent(self, event):
        """Handle dialog close event"""
        if self.change_worker and self.change_worker.isRunning():
            reply = MessageBoxes.show_question(
                self,
                "Operation in Progress",
                "A passphrase change operation is currently running.\n\nAre you sure you want to cancel?"
            )
            
            if reply == MessageBoxes.Yes:
                self.change_worker.terminate()
                self.change_worker.wait()
                event.accept()
            else:
                event.ignore()
        else:
            event.accept()
