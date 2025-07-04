"""
ProfileManagementDialog - User profile management interface for SecurityApp

This module provides comprehensive profile management capabilities including
profile editing, password changes, and account security settings.
"""

from PyQt5.QtWidgets import (QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, 
                             QPushButton, QFrame, QProgressBar, QTextEdit, 
                             QSpacerItem, QSizePolicy, QGroupBox, QTabWidget,
                             QWidget, QDateEdit, QCheckBox, QTableWidget,
                             QTableWidgetItem, QHeaderView)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QThread, pyqtSlot, QDate
from PyQt5.QtGui import QFont, QPixmap

from ..base.base_dialog import BaseDialog
from ..utils.message_boxes import MessageBoxes


class ProfileManagementWorker(QThread):
    """Worker thread for profile management operations."""
    
    operation_completed = pyqtSignal(str, bool, str)  # operation, success, message
    profile_loaded = pyqtSignal(dict)  # profile_data
    
    def __init__(self, auth_controller, operation, user_info, **kwargs):
        super().__init__()
        self.auth_controller = auth_controller
        self.operation = operation
        self.user_info = user_info
        self.kwargs = kwargs
        
    def run(self):
        """Execute the profile operation."""
        try:
            if self.operation == "load_profile":
                # Get account status and details
                account_status = self.auth_controller.get_account_status(self.user_info['email'])
                self.profile_loaded.emit(account_status)
                
            elif self.operation == "update_profile":
                user_id = self.user_info['id']
                name = self.kwargs.get('name')
                phone = self.kwargs.get('phone') 
                address = self.kwargs.get('address')
                birth_date = self.kwargs.get('birth_date')
                
                success, message = self.auth_controller.update_user_profile(
                    user_id, name, phone, address, birth_date
                )
                self.operation_completed.emit("update_profile", success, message)
                
            elif self.operation == "change_password":
                user_id = self.user_info['id']
                current_password = self.kwargs.get('current_password')
                new_password = self.kwargs.get('new_password')
                
                success, message = self.auth_controller.change_passphrase(
                    user_id, current_password, new_password
                )
                self.operation_completed.emit("change_password", success, message)
                
            elif self.operation == "generate_keys":
                user_id = self.user_info['id']
                passphrase = self.kwargs.get('passphrase')
                
                success, message = self.auth_controller.generate_new_keys(user_id, passphrase)
                self.operation_completed.emit("generate_keys", success, message)
                
        except Exception as e:
            self.operation_completed.emit(self.operation, False, f"Operation failed: {str(e)}")


class ProfileManagementDialog(BaseDialog):
    """
    Profile management dialog for user account settings.
    
    This dialog handles:
    - Profile information editing
    - Password changes with validation
    - Key management operations
    - Account security settings
    """
    
    # Signals for profile management
    profile_updated = pyqtSignal(str)  # operation_type
    
    def __init__(self, user_info, auth_controller, parent=None):
        self.user_info = user_info
        self.auth_controller = auth_controller
        self.profile_worker = None
        self.profile_data = {}
        
        super().__init__(parent)
        self.setup_ui()
        self.setup_connections()
        self.load_profile_data()
        
    def setup_ui(self):
        """Setup the profile management dialog UI."""
        self.setWindowTitle(f"Profile Management - {self.user_info['name']}")
        self.setFixedSize(800, 700)
        
        layout = QVBoxLayout()
        layout.setSpacing(20)
        layout.setContentsMargins(30, 30, 30, 30)
        
        # Header
        header_layout = self.create_header()
        layout.addLayout(header_layout)
        
        # Tabbed interface
        self.tab_widget = self.create_tab_interface()
        layout.addWidget(self.tab_widget)
        
        # Action buttons
        button_layout = self.create_action_buttons()
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
        
    def create_header(self):
        """Create the header section."""
        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignCenter)
        
        title_label = QLabel("Profile Management")
        title_font = QFont()
        title_font.setPointSize(18)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setStyleSheet("color: #2c3e50; margin-bottom: 10px;")
        layout.addWidget(title_label)
        
        user_label = QLabel(f"Managing account for: {self.user_info['name']} ({self.user_info['email']})")
        user_label.setAlignment(Qt.AlignCenter)
        user_label.setStyleSheet("color: #7f8c8d; margin-bottom: 20px;")
        layout.addWidget(user_label)
        
        return layout
        
    def create_tab_interface(self):
        """Create the tabbed interface."""
        tab_widget = QTabWidget()
        tab_widget.setStyleSheet("""
            QTabWidget::pane {
                border: 2px solid #bdc3c7;
                border-radius: 5px;
                background-color: white;
            }
            QTabBar::tab {
                background-color: #ecf0f1;
                padding: 12px 20px;
                margin-right: 2px;
                border-top-left-radius: 5px;
                border-top-right-radius: 5px;
                font-weight: bold;
            }
            QTabBar::tab:selected {
                background-color: white;
                border-bottom: 2px solid white;
                color: #2c3e50;
            }
        """)
        
        # Profile Information Tab
        profile_tab = QWidget()
        profile_layout = QVBoxLayout()
        self.create_profile_tab_content(profile_layout)
        profile_tab.setLayout(profile_layout)
        tab_widget.addTab(profile_tab, "Profile Information")
        
        # Security Settings Tab
        security_tab = QWidget()
        security_layout = QVBoxLayout()
        self.create_security_tab_content(security_layout)
        security_tab.setLayout(security_layout)
        tab_widget.addTab(security_tab, "Security Settings")
        
        # Account Status Tab
        status_tab = QWidget()
        status_layout = QVBoxLayout()
        self.create_status_tab_content(status_layout)
        status_tab.setLayout(status_layout)
        tab_widget.addTab(status_tab, "Account Status")
        
        return tab_widget
        
    def create_profile_tab_content(self, layout):
        """Create profile information tab content."""
        # Personal Information Group
        info_group = QGroupBox("Personal Information")
        info_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 2px solid #bdc3c7;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
            }
        """)
        
        info_layout = QVBoxLayout()
        info_layout.setSpacing(15)
        
        # Full Name
        name_label = QLabel("Full Name:")
        name_label.setStyleSheet("font-weight: bold; color: #2c3e50;")
        info_layout.addWidget(name_label)
        
        self.name_field = QLineEdit()
        self.name_field.setPlaceholderText("Enter your full name")
        self.name_field.setStyleSheet("""
            QLineEdit {
                padding: 12px;
                border: 2px solid #bdc3c7;
                border-radius: 5px;
                font-size: 14px;
                background-color: white;
            }
            QLineEdit:focus {
                border-color: #3498db;
            }
        """)
        info_layout.addWidget(self.name_field)
        
        # Email (read-only)
        email_label = QLabel("Email Address:")
        email_label.setStyleSheet("font-weight: bold; color: #2c3e50;")
        info_layout.addWidget(email_label)
        
        self.email_field = QLineEdit()
        self.email_field.setText(self.user_info['email'])
        self.email_field.setReadOnly(True)
        self.email_field.setStyleSheet("""
            QLineEdit {
                padding: 12px;
                border: 2px solid #bdc3c7;
                border-radius: 5px;
                font-size: 14px;
                background-color: #f8f9fa;
                color: #6c757d;
            }
        """)
        info_layout.addWidget(self.email_field)
        
        # Phone
        phone_label = QLabel("Phone Number:")
        phone_label.setStyleSheet("font-weight: bold; color: #2c3e50;")
        info_layout.addWidget(phone_label)
        
        self.phone_field = QLineEdit()
        self.phone_field.setPlaceholderText("Enter phone number (optional)")
        self.phone_field.setStyleSheet("""
            QLineEdit {
                padding: 12px;
                border: 2px solid #bdc3c7;
                border-radius: 5px;
                font-size: 14px;
                background-color: white;
            }
            QLineEdit:focus {
                border-color: #3498db;
            }
        """)
        info_layout.addWidget(self.phone_field)
        
        # Address
        address_label = QLabel("Address:")
        address_label.setStyleSheet("font-weight: bold; color: #2c3e50;")
        info_layout.addWidget(address_label)
        
        self.address_field = QTextEdit()
        self.address_field.setPlaceholderText("Enter address (optional)")
        self.address_field.setMaximumHeight(80)
        self.address_field.setStyleSheet("""
            QTextEdit {
                padding: 12px;
                border: 2px solid #bdc3c7;
                border-radius: 5px;
                font-size: 14px;
                background-color: white;
            }
            QTextEdit:focus {
                border-color: #3498db;
            }
        """)
        info_layout.addWidget(self.address_field)
        
        # Birth Date
        birth_label = QLabel("Birth Date:")
        birth_label.setStyleSheet("font-weight: bold; color: #2c3e50;")
        info_layout.addWidget(birth_label)
        
        self.birth_date_field = QDateEdit()
        self.birth_date_field.setCalendarPopup(True)
        self.birth_date_field.setDate(QDate.currentDate().addYears(-25))
        self.birth_date_field.setStyleSheet("""
            QDateEdit {
                padding: 12px;
                border: 2px solid #bdc3c7;
                border-radius: 5px;
                font-size: 14px;
                background-color: white;
            }
            QDateEdit:focus {
                border-color: #3498db;
            }
        """)
        info_layout.addWidget(self.birth_date_field)
        
        # Save Profile Button
        self.save_profile_btn = QPushButton("Save Profile Changes")
        self.save_profile_btn.setStyleSheet("""
            QPushButton {
                background-color: #27ae60;
                color: white;
                border: none;
                padding: 12px;
                border-radius: 5px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #229954;
            }
            QPushButton:pressed {
                background-color: #1e8449;
            }
            QPushButton:disabled {
                background-color: #bdc3c7;
                color: #7f8c8d;
            }
        """)
        info_layout.addWidget(self.save_profile_btn)
        
        info_group.setLayout(info_layout)
        layout.addWidget(info_group)
        
    def create_security_tab_content(self, layout):
        """Create security settings tab content."""
        # Password Change Group
        password_group = QGroupBox("Change Password")
        password_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 2px solid #bdc3c7;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
            }
        """)
        
        password_layout = QVBoxLayout()
        password_layout.setSpacing(15)
        
        # Current Password
        current_label = QLabel("Current Password:")
        current_label.setStyleSheet("font-weight: bold; color: #2c3e50;")
        password_layout.addWidget(current_label)
        
        self.current_password_field = QLineEdit()
        self.current_password_field.setPlaceholderText("Enter current password")
        self.current_password_field.setEchoMode(QLineEdit.Password)
        self.current_password_field.setStyleSheet("""
            QLineEdit {
                padding: 12px;
                border: 2px solid #bdc3c7;
                border-radius: 5px;
                font-size: 14px;
                background-color: white;
            }
            QLineEdit:focus {
                border-color: #3498db;
            }
        """)
        password_layout.addWidget(self.current_password_field)
        
        # New Password
        new_label = QLabel("New Password:")
        new_label.setStyleSheet("font-weight: bold; color: #2c3e50;")
        password_layout.addWidget(new_label)
        
        self.new_password_field = QLineEdit()
        self.new_password_field.setPlaceholderText("Enter new password")
        self.new_password_field.setEchoMode(QLineEdit.Password)
        self.new_password_field.setStyleSheet("""
            QLineEdit {
                padding: 12px;
                border: 2px solid #bdc3c7;
                border-radius: 5px;
                font-size: 14px;
                background-color: white;
            }
            QLineEdit:focus {
                border-color: #3498db;
            }
        """)
        password_layout.addWidget(self.new_password_field)
        
        # Confirm New Password
        confirm_label = QLabel("Confirm New Password:")
        confirm_label.setStyleSheet("font-weight: bold; color: #2c3e50;")
        password_layout.addWidget(confirm_label)
        
        self.confirm_password_field = QLineEdit()
        self.confirm_password_field.setPlaceholderText("Confirm new password")
        self.confirm_password_field.setEchoMode(QLineEdit.Password)
        self.confirm_password_field.setStyleSheet("""
            QLineEdit {
                padding: 12px;
                border: 2px solid #bdc3c7;
                border-radius: 5px;
                font-size: 14px;
                background-color: white;
            }
            QLineEdit:focus {
                border-color: #3498db;
            }
        """)
        password_layout.addWidget(self.confirm_password_field)
        
        # Password strength indicator
        self.password_strength_label = QLabel("")
        self.password_strength_label.setStyleSheet("color: #7f8c8d; font-size: 12px;")
        password_layout.addWidget(self.password_strength_label)
        
        # Change Password Button
        self.change_password_btn = QPushButton("Change Password")
        self.change_password_btn.setEnabled(False)
        self.change_password_btn.setStyleSheet("""
            QPushButton {
                background-color: #e74c3c;
                color: white;
                border: none;
                padding: 12px;
                border-radius: 5px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #c0392b;
            }
            QPushButton:pressed {
                background-color: #a93226;
            }
            QPushButton:disabled {
                background-color: #bdc3c7;
                color: #7f8c8d;
            }
        """)
        password_layout.addWidget(self.change_password_btn)
        
        password_group.setLayout(password_layout)
        layout.addWidget(password_group)
        
        # Key Management Group
        key_group = QGroupBox("RSA Key Management")
        key_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 2px solid #bdc3c7;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
            }
        """)
        
        key_layout = QVBoxLayout()
        key_layout.setSpacing(15)
        
        # Key status
        self.key_status_label = QLabel("Loading key information...")
        self.key_status_label.setStyleSheet("color: #7f8c8d; font-style: italic;")
        key_layout.addWidget(self.key_status_label)
        
        # Generate New Keys Button
        self.generate_keys_btn = QPushButton("Generate New RSA Keys")
        self.generate_keys_btn.setStyleSheet("""
            QPushButton {
                background-color: #f39c12;
                color: white;
                border: none;
                padding: 12px;
                border-radius: 5px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #e67e22;
            }
            QPushButton:pressed {
                background-color: #d35400;
            }
            QPushButton:disabled {
                background-color: #bdc3c7;
                color: #7f8c8d;
            }
        """)
        key_layout.addWidget(self.generate_keys_btn)
        
        key_group.setLayout(key_layout)
        layout.addWidget(key_group)
        
        # Add spacer
        layout.addItem(QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding))
        
    def create_status_tab_content(self, layout):
        """Create account status tab content."""
        # Account Information Group
        account_group = QGroupBox("Account Information")
        account_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 2px solid #bdc3c7;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
            }
        """)
        
        account_layout = QVBoxLayout()
        account_layout.setSpacing(15)
        
        # Account status table
        self.status_table = QTableWidget()
        self.status_table.setColumnCount(2)
        self.status_table.setHorizontalHeaderLabels(["Property", "Value"])
        self.status_table.horizontalHeader().setStretchLastSection(True)
        self.status_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.status_table.setAlternatingRowColors(True)
        self.status_table.setStyleSheet("""
            QTableWidget {
                border: 1px solid #bdc3c7;
                border-radius: 5px;
                background-color: white;
                gridline-color: #ecf0f1;
            }
            QTableWidget::item {
                padding: 8px;
                border-bottom: 1px solid #ecf0f1;
            }
            QHeaderView::section {
                background-color: #34495e;
                color: white;
                padding: 10px;
                border: none;
                font-weight: bold;
            }
        """)
        account_layout.addWidget(self.status_table)
        
        account_group.setLayout(account_layout)
        layout.addWidget(account_group)
        
        # Progress section
        self.progress_label = QLabel("Loading account information...")
        self.progress_label.setStyleSheet("color: #7f8c8d; font-style: italic;")
        layout.addWidget(self.progress_label)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 2px solid #bdc3c7;
                border-radius: 5px;
                text-align: center;
            }
            QProgressBar::chunk {
                background-color: #3498db;
                border-radius: 3px;
            }
        """)
        layout.addWidget(self.progress_bar)
        
    def create_action_buttons(self):
        """Create action buttons."""
        layout = QHBoxLayout()
        layout.setSpacing(15)
        
        # Add spacer
        layout.addItem(QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum))
        
        # Refresh Data button
        self.refresh_btn = QPushButton("Refresh Data")
        self.refresh_btn.setStyleSheet("""
            QPushButton {
                background-color: #3498db;
                color: white;
                border: none;
                padding: 12px 24px;
                border-radius: 5px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
            QPushButton:pressed {
                background-color: #21618c;
            }
        """)
        layout.addWidget(self.refresh_btn)
        
        # Close button
        self.close_btn = QPushButton("Close")
        self.close_btn.setStyleSheet("""
            QPushButton {
                background-color: #95a5a6;
                color: white;
                border: none;
                padding: 12px 24px;
                border-radius: 5px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #7f8c8d;
            }
            QPushButton:pressed {
                background-color: #6c7b7d;
            }
        """)
        layout.addWidget(self.close_btn)
        
        return layout
        
    def setup_connections(self):
        """Setup signal connections."""
        # Profile tab connections
        self.save_profile_btn.clicked.connect(self.save_profile_changes)
        
        # Security tab connections
        self.current_password_field.textChanged.connect(self.validate_password_change)
        self.new_password_field.textChanged.connect(self.validate_password_change)
        self.confirm_password_field.textChanged.connect(self.validate_password_change)
        self.change_password_btn.clicked.connect(self.change_password)
        self.generate_keys_btn.clicked.connect(self.generate_new_keys)
        
        # Action button connections
        self.refresh_btn.clicked.connect(self.load_profile_data)
        self.close_btn.clicked.connect(self.accept)
        
    def load_profile_data(self):
        """Load profile data from backend."""
        self.progress_label.setText("Loading profile data...")
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate progress
        
        self.profile_worker = ProfileManagementWorker(
            self.auth_controller,
            "load_profile",
            self.user_info
        )
        self.profile_worker.profile_loaded.connect(self.handle_profile_loaded)
        self.profile_worker.start()
        
    @pyqtSlot(dict)
    def handle_profile_loaded(self, profile_data):
        """Handle loaded profile data."""
        self.progress_bar.setVisible(False)
        self.profile_data = profile_data
        
        # Update profile tab fields
        if 'name' in profile_data:
            self.name_field.setText(profile_data['name'])
        if 'phone' in profile_data:
            self.phone_field.setText(profile_data['phone'] or "")
        if 'address' in profile_data:
            self.address_field.setPlainText(profile_data['address'] or "")
        if 'birth_date' in profile_data and profile_data['birth_date']:
            try:
                birth_date = QDate.fromString(profile_data['birth_date'], "yyyy-MM-dd")
                self.birth_date_field.setDate(birth_date)
            except:
                pass
                
        # Update key status
        if 'key_count' in profile_data:
            key_count = profile_data['key_count']
            if key_count > 0:
                self.key_status_label.setText(f"✅ {key_count} RSA key(s) available")
                self.key_status_label.setStyleSheet("color: #27ae60; font-weight: bold;")
            else:
                self.key_status_label.setText("⚠️ No RSA keys found")
                self.key_status_label.setStyleSheet("color: #e74c3c; font-weight: bold;")
        
        # Update status table
        self.update_status_table(profile_data)
        self.progress_label.setText("Profile data loaded successfully")
        
    def update_status_table(self, data):
        """Update the account status table."""
        status_items = [
            ("User ID", str(data.get('id', 'N/A'))),
            ("Email", data.get('email', 'N/A')),
            ("Name", data.get('name', 'N/A')),
            ("Phone", data.get('phone', 'Not set')),
            ("Address", data.get('address', 'Not set')),
            ("Birth Date", data.get('birth_date', 'Not set')),
            ("Registration Date", data.get('created_at', 'N/A')),
            ("Last Login", data.get('last_login', 'N/A')),
            ("Failed Attempts", str(data.get('failed_attempts', 0))),
            ("Account Status", "Active" if not data.get('locked_until') else "Locked"),
            ("RSA Keys", str(data.get('key_count', 0))),
            ("Total Logins", str(data.get('total_logins', 0)))
        ]
        
        self.status_table.setRowCount(len(status_items))
        
        for row, (property_name, value) in enumerate(status_items):
            property_item = QTableWidgetItem(property_name)
            property_item.setFlags(property_item.flags() & ~Qt.ItemIsEditable)
            
            value_item = QTableWidgetItem(str(value))
            value_item.setFlags(value_item.flags() & ~Qt.ItemIsEditable)
            
            self.status_table.setItem(row, 0, property_item)
            self.status_table.setItem(row, 1, value_item)
            
    def validate_password_change(self):
        """Validate password change fields."""
        current = self.current_password_field.text()
        new_password = self.new_password_field.text()
        confirm = self.confirm_password_field.text()
        
        # Check if all fields are filled
        if not all([current, new_password, confirm]):
            self.change_password_btn.setEnabled(False)
            self.password_strength_label.setText("")
            return
            
        # Check password strength
        try:
            success, message = self.auth_controller.validate_password_strength(new_password)
            if not success:
                self.password_strength_label.setText(f"❌ {message}")
                self.password_strength_label.setStyleSheet("color: #e74c3c; font-size: 12px;")
                self.change_password_btn.setEnabled(False)
                return
        except:
            self.change_password_btn.setEnabled(False)
            return
            
        # Check password matching
        if new_password != confirm:
            self.password_strength_label.setText("❌ Passwords do not match")
            self.password_strength_label.setStyleSheet("color: #e74c3c; font-size: 12px;")
            self.change_password_btn.setEnabled(False)
            return
            
        # All validations passed
        self.password_strength_label.setText("✅ Password is valid")
        self.password_strength_label.setStyleSheet("color: #27ae60; font-size: 12px;")
        self.change_password_btn.setEnabled(True)
        
    def save_profile_changes(self):
        """Save profile changes."""
        name = self.name_field.text().strip()
        phone = self.phone_field.text().strip() or None
        address = self.address_field.toPlainText().strip() or None
        birth_date = self.birth_date_field.date().toString("yyyy-MM-dd") if self.birth_date_field.date() != QDate.currentDate().addYears(-25) else None
        
        if not name:
            MessageBoxes.warning(self, "Invalid Input", "Name is required.")
            return
            
        # Confirm changes
        reply = MessageBoxes.confirmation(
            self, "Confirm Profile Changes",
            "Are you sure you want to save these profile changes?"
        )
        
        if not reply:
            return
            
        # Start update operation
        self.save_profile_btn.setEnabled(False)
        self.progress_label.setText("Saving profile changes...")
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)
        
        self.profile_worker = ProfileManagementWorker(
            self.auth_controller,
            "update_profile",
            self.user_info,
            name=name,
            phone=phone,
            address=address,
            birth_date=birth_date
        )
        self.profile_worker.operation_completed.connect(self.handle_operation_result)
        self.profile_worker.start()
        
    def change_password(self):
        """Change user password."""
        current_password = self.current_password_field.text()
        new_password = self.new_password_field.text()
        
        # Confirm password change
        reply = MessageBoxes.confirmation(
            self, "Confirm Password Change",
            "Are you sure you want to change your password?\n\n"
            "This will re-encrypt all your RSA keys with the new password."
        )
        
        if not reply:
            return
            
        # Start password change operation
        self.change_password_btn.setEnabled(False)
        self.progress_label.setText("Changing password...")
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)
        
        self.profile_worker = ProfileManagementWorker(
            self.auth_controller,
            "change_password",
            self.user_info,
            current_password=current_password,
            new_password=new_password
        )
        self.profile_worker.operation_completed.connect(self.handle_operation_result)
        self.profile_worker.start()
        
    def generate_new_keys(self):
        """Generate new RSA keys."""
        # Get passphrase for key generation
        passphrase, ok = MessageBoxes.password_input(
            self, "Key Generation Passphrase",
            "Enter your current password for key generation:"
        )
        
        if not ok or not passphrase:
            return
            
        # Confirm key generation
        reply = MessageBoxes.confirmation(
            self, "Confirm Key Generation",
            "Are you sure you want to generate new RSA keys?\n\n"
            "This will create new keys while keeping existing ones available."
        )
        
        if not reply:
            return
            
        # Start key generation operation
        self.generate_keys_btn.setEnabled(False)
        self.progress_label.setText("Generating new RSA keys...")
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)
        
        self.profile_worker = ProfileManagementWorker(
            self.auth_controller,
            "generate_keys",
            self.user_info,
            passphrase=passphrase
        )
        self.profile_worker.operation_completed.connect(self.handle_operation_result)
        self.profile_worker.start()
        
    @pyqtSlot(str, bool, str)
    def handle_operation_result(self, operation, success, message):
        """Handle operation result."""
        self.progress_bar.setVisible(False)
        
        # Re-enable buttons
        if operation == "update_profile":
            self.save_profile_btn.setEnabled(True)
        elif operation == "change_password":
            self.change_password_btn.setEnabled(True)
            # Clear password fields on success
            if success:
                self.current_password_field.clear()
                self.new_password_field.clear()
                self.confirm_password_field.clear()
        elif operation == "generate_keys":
            self.generate_keys_btn.setEnabled(True)
            
        if success:
            self.progress_label.setText(f"✅ {operation.replace('_', ' ').title()} completed successfully")
            MessageBoxes.info(self, "Operation Successful", message)
            self.profile_updated.emit(operation)
            
            # Reload profile data to reflect changes
            if operation in ["update_profile", "generate_keys"]:
                self.load_profile_data()
        else:
            self.progress_label.setText(f"❌ {operation.replace('_', ' ').title()} failed")
            MessageBoxes.show_error(self, "Operation Failed", message)
            
    def closeEvent(self, event):
        """Handle dialog close event."""
        # Stop any running worker threads
        if self.profile_worker and self.profile_worker.isRunning():
            self.profile_worker.terminate()
            self.profile_worker.wait()
        event.accept()
