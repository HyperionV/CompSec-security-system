from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, 
                             QPushButton, QLabel, QLineEdit, QFormLayout,
                             QTableWidget, QTableWidgetItem, QHeaderView)
from PyQt5.QtCore import Qt
from ..utils.dialogs import (show_error, show_info, show_warning, show_question, 
                            PasswordDialog)

class AccountTab(QWidget):
    def __init__(self, user_session, managers, parent=None):
        super().__init__(parent)
        self.user_session = user_session
        self.managers = managers
        self.auth_manager = managers['auth_manager']
        self.db = managers['db']
        self.setup_ui()
        self.load_user_data()
        self.refresh_activity_log()
    
    def setup_ui(self):
        layout = QVBoxLayout()
        
        # Profile Information Section
        profile_group = QGroupBox("Profile Information")
        profile_layout = QFormLayout()
        
        self.name_input = QLineEdit()
        profile_layout.addRow("Full Name:", self.name_input)
        
        self.email_label = QLabel()
        self.email_label.setStyleSheet("color: #666; font-style: italic;")
        profile_layout.addRow("Email:", self.email_label)
        
        self.phone_input = QLineEdit()
        self.phone_input.setPlaceholderText("Optional")
        profile_layout.addRow("Phone:", self.phone_input)
        
        self.address_input = QLineEdit()
        self.address_input.setPlaceholderText("Optional")
        profile_layout.addRow("Address:", self.address_input)
        
        self.birth_date_input = QLineEdit()
        self.birth_date_input.setPlaceholderText("YYYY-MM-DD (Optional)")
        profile_layout.addRow("Birth Date:", self.birth_date_input)
        
        # Update profile button
        self.update_profile_button = QPushButton("Update Profile")
        self.update_profile_button.clicked.connect(self.update_profile)
        profile_layout.addRow("", self.update_profile_button)
        
        profile_group.setLayout(profile_layout)
        layout.addWidget(profile_group)
        
        # Password Change Section
        password_group = QGroupBox("Change Passphrase")
        password_layout = QVBoxLayout()
        
        password_info = QLabel("Change your account passphrase. This will re-encrypt your private keys.")
        password_info.setWordWrap(True)
        password_info.setStyleSheet("color: #666; font-style: italic;")
        password_layout.addWidget(password_info)
        
        self.change_password_button = QPushButton("Change Passphrase")
        self.change_password_button.clicked.connect(self.change_passphrase)
        password_layout.addWidget(self.change_password_button)
        
        password_group.setLayout(password_layout)
        layout.addWidget(password_group)
        
        # Activity Log Section
        activity_group = QGroupBox("Recent Activity")
        activity_layout = QVBoxLayout()
        
        self.activity_table = QTableWidget()
        self.activity_table.setColumnCount(4)
        self.activity_table.setHorizontalHeaderLabels([
            "Date/Time", "Action", "Status", "Details"
        ])
        
        # Set column resize mode
        header = self.activity_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.Stretch)
        
        self.activity_table.setMaximumHeight(200)
        activity_layout.addWidget(self.activity_table)
        
        # Refresh button
        refresh_button = QPushButton("Refresh Activity Log")
        refresh_button.clicked.connect(self.refresh_activity_log)
        activity_layout.addWidget(refresh_button)
        
        activity_group.setLayout(activity_layout)
        layout.addWidget(activity_group)
        
        layout.addStretch()
        self.setLayout(layout)
    
    def load_user_data(self):
        """Load current user data into form fields"""
        user_info = self.user_session.user_info
        
        self.name_input.setText(user_info.get('name', ''))
        self.email_label.setText(user_info.get('email', ''))
        self.phone_input.setText(user_info.get('phone', '') or '')
        self.address_input.setText(user_info.get('address', '') or '')
        self.birth_date_input.setText(user_info.get('birth_date', '') or '')
    
    def update_profile(self):
        """Update user profile information"""
        try:
            name = self.name_input.text().strip()
            phone = self.phone_input.text().strip() or None
            address = self.address_input.text().strip() or None
            birth_date = self.birth_date_input.text().strip() or None
            
            if not name:
                show_warning(self, "Validation Error", "Name is required.")
                return
            
            # Validate birth date format if provided
            if birth_date:
                try:
                    from datetime import datetime
                    datetime.strptime(birth_date, '%Y-%m-%d')
                except ValueError:
                    show_warning(self, "Validation Error", "Birth date must be in YYYY-MM-DD format.")
                    return
            
            # Update profile
            success, message = self.auth_manager.update_user_profile(
                self.user_session.user_info['id'],
                name=name,
                phone=phone,
                address=address,
                birth_date=birth_date
            )
            
            if success:
                show_info(self, "Success", message)
                # Update session info
                self.user_session.user_info.update({
                    'name': name,
                    'phone': phone,
                    'address': address,
                    'birth_date': birth_date
                })
                self.refresh_activity_log()
            else:
                show_error(self, "Update Failed", message)
                
        except Exception as e:
            show_error(self, "Error", f"Failed to update profile: {str(e)}")
    
    def change_passphrase(self):
        """Change user passphrase"""
        try:
            # Get current passphrase
            current_dialog = PasswordDialog("Change Passphrase", "Current passphrase:", self)
            if current_dialog.exec_() != current_dialog.Accepted:
                return
            
            current_passphrase = current_dialog.get_password()
            if not current_passphrase:
                show_error(self, "Error", "Current passphrase is required.")
                return
            
            # Get new passphrase
            new_dialog = PasswordDialog("Change Passphrase", "New passphrase:", self)
            if new_dialog.exec_() != new_dialog.Accepted:
                return
            
            new_passphrase = new_dialog.get_password()
            if not new_passphrase:
                show_error(self, "Error", "New passphrase is required.")
                return
            
            # Confirm new passphrase
            confirm_dialog = PasswordDialog("Change Passphrase", "Confirm new passphrase:", self)
            if confirm_dialog.exec_() != confirm_dialog.Accepted:
                return
            
            confirm_passphrase = confirm_dialog.get_password()
            if new_passphrase != confirm_passphrase:
                show_error(self, "Error", "New passphrases do not match.")
                return
            
            # Confirm operation
            if not show_question(self, "Change Passphrase", 
                               "This will change your passphrase and re-encrypt your private keys. Continue?"):
                return
            
            # Change passphrase
            success, message = self.auth_manager.change_passphrase(
                self.user_session.user_info['id'],
                current_passphrase,
                new_passphrase
            )
            
            if success:
                show_info(self, "Success", message)
                self.refresh_activity_log()
            else:
                show_error(self, "Change Failed", message)
                
        except Exception as e:
            show_error(self, "Error", f"Failed to change passphrase: {str(e)}")
    
    def refresh_activity_log(self):
        """Refresh the activity log table"""
        try:
            # Get user activity logs
            logs = self.db.get_user_activity_logs(self.user_session.user_info['id'], limit=20)
            
            # Clear and populate table
            self.activity_table.setRowCount(0)
            
            for log in logs:
                self.add_log_to_table(log)
                
        except Exception as e:
            show_error(self, "Error", f"Failed to refresh activity log: {str(e)}")
    
    def add_log_to_table(self, log_data):
        """Add a log entry to the table"""
        row = self.activity_table.rowCount()
        self.activity_table.insertRow(row)
        
        # Format timestamp
        timestamp = log_data['timestamp']
        if 'T' in timestamp:
            date_part, time_part = timestamp.split('T')
            if '.' in time_part:
                time_part = time_part.split('.')[0]
            formatted_time = f"{date_part} {time_part}"
        else:
            formatted_time = timestamp
        
        self.activity_table.setItem(row, 0, QTableWidgetItem(formatted_time))
        self.activity_table.setItem(row, 1, QTableWidgetItem(log_data['action']))
        self.activity_table.setItem(row, 2, QTableWidgetItem(log_data['status']))
        self.activity_table.setItem(row, 3, QTableWidgetItem(log_data.get('details', '')))
    
    def refresh_data(self):
        """Refresh tab data"""
        self.load_user_data()
        self.refresh_activity_log() 