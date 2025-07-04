from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTabWidget,
                             QFormLayout, QPushButton, QLabel, QGroupBox, 
                             QLineEdit, QDateEdit, QTextEdit, QCheckBox)
from PyQt5.QtCore import Qt, QDate, QThread, pyqtSignal
from PyQt5.QtGui import QFont
from ..base.base_window import BaseWindow
from ..utils.message_boxes import MessageBoxes
from modules.auth import AuthManager

class ProfileUpdateWorker(QThread):
    finished = pyqtSignal(bool, str)
    
    def __init__(self, user_id, name, phone, address, birth_date):
        super().__init__()
        self.user_id = user_id
        self.name = name
        self.phone = phone
        self.address = address
        self.birth_date = birth_date
        
    def run(self):
        try:
            auth_manager = AuthManager()
            success, message = auth_manager.update_user_profile(
                self.user_id, self.name, self.phone, self.address, self.birth_date
            )
            self.finished.emit(success, message)
        except Exception as e:
            self.finished.emit(False, str(e))

class AccountSettingsWindow(BaseWindow):
    def __init__(self, session_manager, parent=None):
        super().__init__("Account Settings", parent)
        self.session_manager = session_manager
        self.auth_manager = AuthManager()
        self.setup_ui()
        self.load_user_data()
    
    def setup_ui(self):
        self.setFixedSize(800, 700)
        
        header = QLabel("Account Settings")
        header.setFont(QFont("Arial", 16, QFont.Bold))
        header.setAlignment(Qt.AlignCenter)
        self.main_layout.addWidget(header)
        
        self.tab_widget = QTabWidget()
        
        self.profile_tab = self.create_profile_tab()
        self.security_tab = self.create_security_tab()
        self.recovery_tab = self.create_recovery_tab()
        
        self.tab_widget.addTab(self.profile_tab, "Profile Information")
        self.tab_widget.addTab(self.security_tab, "Security Settings")
        self.tab_widget.addTab(self.recovery_tab, "Account Recovery")
        
        self.main_layout.addWidget(self.tab_widget)
        
        button_layout = QHBoxLayout()
        
        self.close_button = QPushButton("Close")
        self.close_button.clicked.connect(self.close)
        
        button_layout.addStretch()
        button_layout.addWidget(self.close_button)
        
        self.main_layout.addLayout(button_layout)
    
    def create_profile_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        profile_group = QGroupBox("Personal Information")
        profile_layout = QFormLayout(profile_group)
        
        self.name_input = QLineEdit()
        self.email_label = QLabel()
        self.email_label.setStyleSheet("color: #6c757d; font-style: italic;")
        self.phone_input = QLineEdit()
        self.phone_input.setPlaceholderText("e.g., +1-555-123-4567")
        
        self.birth_date_input = QDateEdit()
        self.birth_date_input.setCalendarPopup(True)
        self.birth_date_input.setDisplayFormat("yyyy-MM-dd")
        
        self.address_input = QTextEdit()
        self.address_input.setMaximumHeight(80)
        self.address_input.setPlaceholderText("Enter your address...")
        
        profile_layout.addRow("Name:", self.name_input)
        profile_layout.addRow("Email:", self.email_label)
        profile_layout.addRow("Phone:", self.phone_input)
        profile_layout.addRow("Birth Date:", self.birth_date_input)
        profile_layout.addRow("Address:", self.address_input)
        
        layout.addWidget(profile_group)
        
        button_layout = QHBoxLayout()
        
        self.save_profile_button = QPushButton("Save Changes")
        self.save_profile_button.clicked.connect(self.save_profile_changes)
        
        self.reset_profile_button = QPushButton("Reset")
        self.reset_profile_button.clicked.connect(self.reset_profile_form)
        
        button_layout.addWidget(self.save_profile_button)
        button_layout.addWidget(self.reset_profile_button)
        button_layout.addStretch()
        
        layout.addLayout(button_layout)
        layout.addStretch()
        
        return tab
    
    def create_security_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        passphrase_group = QGroupBox("Change Passphrase")
        passphrase_layout = QVBoxLayout(passphrase_group)
        
        info_label = QLabel("Changing your passphrase will re-encrypt all your RSA keys.")
        info_label.setStyleSheet("color: #856404; background-color: #fff3cd; padding: 8px; border-radius: 3px;")
        info_label.setWordWrap(True)
        passphrase_layout.addWidget(info_label)
        
        self.change_passphrase_button = QPushButton("Change Passphrase")
        self.change_passphrase_button.clicked.connect(self.open_passphrase_change)
        self.change_passphrase_button.setMinimumHeight(40)
        
        passphrase_layout.addWidget(self.change_passphrase_button)
        layout.addWidget(passphrase_group)
        
        keys_group = QGroupBox("Key Management")
        keys_layout = QVBoxLayout(keys_group)
        
        self.view_keys_button = QPushButton("View My Keys")
        self.view_keys_button.clicked.connect(self.view_keys)
        
        self.generate_keys_button = QPushButton("Generate New Keys")
        self.generate_keys_button.clicked.connect(self.generate_new_keys)
        
        keys_layout.addWidget(self.view_keys_button)
        keys_layout.addWidget(self.generate_keys_button)
        layout.addWidget(keys_group)
        
        session_group = QGroupBox("Session Settings")
        session_layout = QVBoxLayout(session_group)
        
        self.auto_logout_checkbox = QCheckBox("Auto-logout after 30 minutes")
        self.auto_logout_checkbox.setChecked(True)
        self.auto_logout_checkbox.setEnabled(False)
        
        session_layout.addWidget(self.auto_logout_checkbox)
        layout.addWidget(session_group)
        
        layout.addStretch()
        return tab
    
    def create_recovery_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        recovery_group = QGroupBox("Account Recovery")
        recovery_layout = QVBoxLayout(recovery_group)
        
        info_label = QLabel("Your recovery code was provided during registration. Keep it safe!")
        info_label.setStyleSheet("color: #721c24; background-color: #f8d7da; padding: 8px; border-radius: 3px;")
        info_label.setWordWrap(True)
        recovery_layout.addWidget(info_label)
        
        self.recovery_info_label = QLabel("Recovery code is set and active.")
        self.recovery_info_label.setStyleSheet("color: #155724; font-weight: bold;")
        recovery_layout.addWidget(self.recovery_info_label)
        
        recovery_layout.addWidget(QLabel("If you've lost your recovery code, contact an administrator."))
        
        layout.addWidget(recovery_group)
        
        backup_group = QGroupBox("Data Backup")
        backup_layout = QVBoxLayout(backup_group)
        
        self.export_data_button = QPushButton("Export Account Data")
        self.export_data_button.clicked.connect(self.export_account_data)
        self.export_data_button.setEnabled(False)
        
        backup_layout.addWidget(self.export_data_button)
        backup_layout.addWidget(QLabel("Note: Sensitive key data will not be included in exports."))
        
        layout.addWidget(backup_group)
        layout.addStretch()
        return tab
    
    def load_user_data(self):
        """Load current user data into form fields"""
        if not self.session_manager.is_authenticated():
            return
            
        user = self.session_manager.current_user
        if not user:
            return
            
        self.email_label.setText(user.get('email', 'Unknown'))
        self.name_input.setText(user.get('name', ''))
        self.phone_input.setText(user.get('phone', ''))
        self.address_input.setPlainText(user.get('address', ''))
        
        if user.get('birth_date'):
            try:
                date_parts = user['birth_date'].split('-')
                if len(date_parts) == 3:
                    year, month, day = map(int, date_parts)
                    self.birth_date_input.setDate(QDate(year, month, day))
            except:
                pass
    
    def reset_profile_form(self):
        """Reset form to original values"""
        self.load_user_data()
        self.update_status("Form reset to original values")
    
    def save_profile_changes(self):
        """Save profile changes"""
        if not self.session_manager.is_authenticated():
            MessageBoxes.show_error(self, "Error", "Not authenticated")
            return
            
        user_id = self.session_manager.get_user_id()
        
        name = self.name_input.text().strip()
        phone = self.phone_input.text().strip()
        address = self.address_input.toPlainText().strip()
        birth_date = self.birth_date_input.date().toString("yyyy-MM-dd")
        
        if not name:
            MessageBoxes.show_error(self, "Validation Error", "Name is required")
            return
            
        self.save_profile_button.setEnabled(False)
        self.save_profile_button.setText("Saving...")
        
        self.profile_worker = ProfileUpdateWorker(user_id, name, phone, address, birth_date)
        self.profile_worker.finished.connect(self.on_profile_update_finished)
        self.profile_worker.start()
    
    def on_profile_update_finished(self, success, message):
        """Handle profile update completion"""
        self.save_profile_button.setEnabled(True)
        self.save_profile_button.setText("Save Changes")
        
        if success:
            MessageBoxes.show_info(self, "Success", "Profile updated successfully!")
            self.update_status("Profile updated successfully")
            if self.session_manager.current_user:
                self.session_manager.current_user.update({
                    'name': self.name_input.text().strip(),
                    'phone': self.phone_input.text().strip(),
                    'address': self.address_input.toPlainText().strip(),
                    'birth_date': self.birth_date_input.date().toString("yyyy-MM-dd")
                })
        else:
            MessageBoxes.show_error(self, "Update Failed", message)
            self.update_status(f"Profile update failed: {message}")
    
    def open_passphrase_change(self):
        """Open passphrase change dialog"""
        from .passphrase_change_dialog import PassphraseChangeDialog
        dialog = PassphraseChangeDialog(self.session_manager, self)
        dialog.exec_()
    
    def view_keys(self):
        """Open key management window"""
        MessageBoxes.show_info(self, "Key Management", 
                             "This will open the Key Management window from the main dashboard.")
    
    def generate_new_keys(self):
        """Generate new RSA keys"""
        reply = MessageBoxes.show_question(self, "Generate New Keys", 
                                         "This will generate new RSA keys. Continue?")
        if reply == MessageBoxes.Yes:
            MessageBoxes.show_info(self, "Key Generation", 
                                 "This will open the Key Generation dialog from the main dashboard.")
    
    def export_account_data(self):
        """Export account data (placeholder)"""
        MessageBoxes.show_info(self, "Export Data", "Account data export feature coming soon.")
