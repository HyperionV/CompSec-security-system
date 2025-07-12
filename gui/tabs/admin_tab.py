from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, 
                             QPushButton, QLabel, QTableWidget, QTableWidgetItem,
                             QHeaderView)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor, QFont
from ..utils.dialogs import show_error, show_info, show_warning

class AdminTab(QWidget):
    def __init__(self, user_session, managers, parent=None):
        super().__init__(parent)
        self.user_session = user_session
        self.managers = managers
        self.db = managers['db']
        self.setup_ui()
        self.refresh_data()
    
    def setup_ui(self):
        layout = QVBoxLayout()
        
        # Admin Info Section
        info_group = QGroupBox("Admin Dashboard")
        info_layout = QVBoxLayout()
        
        admin_label = QLabel(f"Welcome, Administrator {self.user_session.user_info['name']}")
        admin_label.setStyleSheet("font-weight: bold; color: #d9534f;")
        info_layout.addWidget(admin_label)
        
        warning_label = QLabel("⚠️ This is an administrative interface with elevated privileges.")
        warning_label.setStyleSheet("color: #d9534f; font-style: italic;")
        info_layout.addWidget(warning_label)
        
        info_group.setLayout(info_layout)
        layout.addWidget(info_group)
        
        # Users Table
        users_group = QGroupBox("System Users")
        users_layout = QVBoxLayout()
        
        self.users_table = QTableWidget()
        self.users_table.setColumnCount(6)
        self.users_table.setHorizontalHeaderLabels([
            "ID", "Email", "Name", "Role", "Created", "Status"
        ])
        
        # Set column resize mode
        header = self.users_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        header.setSectionResizeMode(2, QHeaderView.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeToContents)
        
        users_layout.addWidget(self.users_table)
        
        # Admin buttons
        admin_buttons = QHBoxLayout()
        
        self.refresh_users_button = QPushButton("Refresh Users")
        self.refresh_users_button.clicked.connect(self.refresh_data)
        admin_buttons.addWidget(self.refresh_users_button)
        
        self.view_logs_button = QPushButton("View System Logs")
        self.view_logs_button.clicked.connect(self.view_system_logs)
        admin_buttons.addWidget(self.view_logs_button)
        
        admin_buttons.addStretch()
        users_layout.addLayout(admin_buttons)
        
        users_group.setLayout(users_layout)
        layout.addWidget(users_group)
        
        # System Information
        system_group = QGroupBox("System Information")
        system_layout = QVBoxLayout()
        
        self.system_info_label = QLabel("Loading system information...")
        system_layout.addWidget(self.system_info_label)
        
        system_group.setLayout(system_layout)
        layout.addWidget(system_group)
        
        layout.addStretch()
        self.setLayout(layout)
    
    def refresh_data(self):
        """Refresh admin data"""
        try:
            # Get all users
            users = self.db.get_all_users_for_admin()
            
            # Clear and populate users table
            self.users_table.setRowCount(0)
            for user in users:
                self.add_user_to_table(user)
            
            # Update system info
            self.update_system_info()
            
        except Exception as e:
            show_error(self, "Error", f"Failed to refresh admin data: {str(e)}")
    
    def add_user_to_table(self, user_data):
        """Add a user to the table"""
        row = self.users_table.rowCount()
        self.users_table.insertRow(row)
        
        # ID
        self.users_table.setItem(row, 0, QTableWidgetItem(str(user_data['id'])))
        
        # Email
        self.users_table.setItem(row, 1, QTableWidgetItem(user_data['email']))
        
        # Name
        self.users_table.setItem(row, 2, QTableWidgetItem(user_data['name']))
        
        # Role
        role = user_data.get('role', 'user').upper()
        role_item = QTableWidgetItem(role)
        if role == 'ADMIN':
            role_item.setForeground(QColor("#d9534f"))
            font = QFont()
            font.setBold(True)
            role_item.setFont(font)
        self.users_table.setItem(row, 3, role_item)
        
        # Created date
        created_date = user_data['created_at'].split('T')[0] if 'T' in user_data['created_at'] else user_data['created_at']
        self.users_table.setItem(row, 4, QTableWidgetItem(created_date))
        
        # Status
        status = "Locked" if user_data.get('is_locked') else "Active"
        status_item = QTableWidgetItem(status)
        if status == "Locked":
            status_item.setForeground(QColor("#d9534f"))
        else:
            status_item.setForeground(QColor("#5cb85c"))
        self.users_table.setItem(row, 5, status_item)
    
    def update_system_info(self):
        """Update system information display"""
        try:
            # Get system statistics
            stats = self.db.get_system_statistics()
            
            info_text = f"Total Users: {stats.get('total_users', 0)}\n"
            info_text += f"Total Keys: {stats.get('total_keys', 0)}\n"
            info_text += f"Total Public Keys: {stats.get('total_public_keys', 0)}\n"
            info_text += f"Recent Activity Logs: {stats.get('recent_activity_count', 0)}"
            
            self.system_info_label.setText(info_text)
            
        except Exception as e:
            self.system_info_label.setText(f"Error loading system info: {str(e)}")
    
    def view_system_logs(self):
        """View system activity logs"""
        try:
            # Get recent system logs
            logs = self.db.get_all_activity_logs(limit=50)
            
            if not logs:
                show_info(self, "System Logs", "No activity logs found.")
                return
            
            # Format logs for display using the new universal format
            log_text = "RECENT SYSTEM ACTIVITY\n"
            log_text += "=" * 50 + "\n\n"
            
            for log in logs:
                timestamp = log['timestamp']
                if 'T' in timestamp:
                    date_part, time_part = timestamp.split('T')
                    if '.' in time_part:
                        time_part = time_part.split('.')[0]
                    formatted_time = f"{date_part} {time_part}"
                else:
                    formatted_time = timestamp
                
                # Use new universal format: [Time] Email:<user_email> Action:<action> Status:<status> Details:<detail>
                user_email = log.get('email', 'None')
                action = log.get('action', 'N/A')
                status = log.get('status', 'unknown')
                details = log.get('details', '')
                
                log_text += f"[{formatted_time}] Email:{user_email} Action:{action} Status:{status} Details:{details}\n\n"
            
            # Show in dialog
            from ..utils.dialogs import InfoDialog
            dialog = InfoDialog("System Activity Logs", log_text, self)
            dialog.exec_()
            
        except Exception as e:
            show_error(self, "Error", f"Failed to load system logs: {str(e)}") 