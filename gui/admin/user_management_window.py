"""
User Management Window
Administrative interface for managing user accounts
"""

from PyQt5.QtWidgets import (QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
                            QPushButton, QLabel, QLineEdit, QHeaderView, QAbstractItemView, QMenu, QAction)
from PyQt5.QtCore import pyqtSignal, Qt, QThread, pyqtSignal as Signal
from PyQt5.QtGui import QFont

from ..base.base_window import BaseWindow
from ..app import session_manager
from ..utils.message_boxes import MessageBoxes
from modules.database import DatabaseManager

class UserDataWorker(QThread):
    """Worker thread for loading user data"""
    data_loaded = Signal(list)
    error_occurred = Signal(str)
    
    def run(self):
        try:
            db = DatabaseManager()
            users = db.get_all_users_for_admin()
            self.data_loaded.emit(users)
        except Exception as e:
            self.error_occurred.emit(str(e))

class UserManagementWindow(BaseWindow):
    """User management interface for administrators"""
    
    # Signals
    user_selected = pyqtSignal(int)  # user_id
    
    def __init__(self, parent=None):
        super().__init__("User Management - Security Application", parent)
        
        # Check admin access
        if not self.check_admin_access():
            self.close()
            return
            
        self.users_data = []
        self.setup_user_management_ui()
        self.load_users()
        self.log_action("user_management_opened", "success", "User management window accessed")
    
    def check_admin_access(self) -> bool:
        """Check if current user has admin privileges"""
        if not session_manager.is_fully_authenticated():
            MessageBoxes.show_error(
                self, 
                "Access Denied", 
                "You must be fully authenticated to access user management."
            )
            return False
        
        if not session_manager.is_admin():
            MessageBoxes.show_error(
                self, 
                "Access Denied", 
                "You do not have administrator privileges."
            )
            return False
        
        return True
    
    def setup_user_management_ui(self):
        """Setup the user management UI"""
        # Header section
        header_layout = QHBoxLayout()
        
        # Title
        title_label = QLabel("User Management")
        title_font = QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        title_label.setFont(title_font)
        
        # Search box
        search_layout = QHBoxLayout()
        search_label = QLabel("Search:")
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Enter email or name...")
        self.search_input.textChanged.connect(self.filter_users)
        
        search_layout.addWidget(search_label)
        search_layout.addWidget(self.search_input)
        search_layout.addStretch()
        
        # Refresh button
        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self.load_users)
        self.refresh_btn.setStyleSheet("""
            QPushButton {
                background-color: #007acc;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #005a9e;
            }
        """)
        
        header_layout.addWidget(title_label)
        header_layout.addStretch()
        header_layout.addLayout(search_layout)
        header_layout.addWidget(self.refresh_btn)
        
        # Users table
        self.users_table = QTableWidget()
        self.setup_users_table()
        
        # Action buttons
        action_layout = QHBoxLayout()
        
        self.lock_btn = QPushButton("Lock User")
        self.lock_btn.clicked.connect(self.lock_selected_user)
        self.lock_btn.setEnabled(False)
        
        self.unlock_btn = QPushButton("Unlock User")
        self.unlock_btn.clicked.connect(self.unlock_selected_user)
        self.unlock_btn.setEnabled(False)
        
        self.delete_btn = QPushButton("Delete User")
        self.delete_btn.clicked.connect(self.delete_selected_user)
        self.delete_btn.setEnabled(False)
        
        self.change_role_btn = QPushButton("Change Role")
        self.change_role_btn.clicked.connect(self.change_user_role)
        self.change_role_btn.setEnabled(False)
        
        # Style action buttons
        button_style = """
            QPushButton {
                background-color: #6c757d;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
                margin: 2px;
            }
            QPushButton:hover {
                background-color: #5a6268;
            }
            QPushButton:disabled {
                background-color: #cccccc;
                color: #666666;
            }
        """
        
        self.lock_btn.setStyleSheet(button_style.replace('#6c757d', '#dc3545').replace('#5a6268', '#c82333'))
        self.unlock_btn.setStyleSheet(button_style.replace('#6c757d', '#28a745').replace('#5a6268', '#218838'))
        self.delete_btn.setStyleSheet(button_style.replace('#6c757d', '#dc3545').replace('#5a6268', '#c82333'))
        self.change_role_btn.setStyleSheet(button_style.replace('#6c757d', '#007bff').replace('#5a6268', '#0056b3'))
        
        action_layout.addWidget(QLabel("Actions:"))
        action_layout.addWidget(self.lock_btn)
        action_layout.addWidget(self.unlock_btn)
        action_layout.addWidget(self.delete_btn)
        action_layout.addWidget(self.change_role_btn)
        action_layout.addStretch()
        
        # Main layout
        self.main_layout.addLayout(header_layout)
        self.main_layout.addWidget(self.users_table)
        self.main_layout.addLayout(action_layout)
        
        self.update_status("Ready - Click Refresh to load users")
    
    def setup_users_table(self):
        """Setup the users table widget"""
        # Table columns
        columns = ["ID", "Email", "Name", "Role", "Status", "Created At", "Last Login"]
        self.users_table.setColumnCount(len(columns))
        self.users_table.setHorizontalHeaderLabels(columns)
        
        # Table properties
        self.users_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.users_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.users_table.setAlternatingRowColors(True)
        self.users_table.setSortingEnabled(True)
        self.users_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.users_table.customContextMenuRequested.connect(self.show_context_menu)
        
        # Column widths
        header = self.users_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)  # ID
        header.setSectionResizeMode(1, QHeaderView.Stretch)  # Email
        header.setSectionResizeMode(2, QHeaderView.Stretch)  # Name
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)  # Role
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)  # Status
        header.setSectionResizeMode(5, QHeaderView.ResizeToContents)  # Created
        header.setSectionResizeMode(6, QHeaderView.ResizeToContents)  # Last Login
        
        # Table styling
        self.users_table.setStyleSheet("""
            QTableWidget {
                border: 1px solid #ddd;
                background-color: white;
                gridline-color: #f0f0f0;
            }
            QTableWidget::item {
                padding: 8px;
                border-bottom: 1px solid #f0f0f0;
            }
            QTableWidget::item:selected {
                background-color: #0078d4;
                color: white;
            }
            QHeaderView::section {
                background-color: #f8f9fa;
                padding: 8px;
                border: none;
                border-bottom: 2px solid #dee2e6;
                font-weight: bold;
            }
        """)
        
        # Row selection signal
        self.users_table.itemSelectionChanged.connect(self.on_user_selection_changed)
    
    def load_users(self):
        """Load users from database"""
        self.update_status("Loading users...")
        self.refresh_btn.setText("Loading...")
        self.refresh_btn.setEnabled(False)
        
        # Create and start worker thread
        self.worker = UserDataWorker()
        self.worker.data_loaded.connect(self.on_users_loaded)
        self.worker.error_occurred.connect(self.on_load_error)
        self.worker.start()
    
    def on_users_loaded(self, users):
        """Handle successful user data load"""
        self.users_data = users
        self.populate_users_table(users)
        self.update_status(f"Loaded {len(users)} users")
        self.refresh_btn.setText("Refresh")
        self.refresh_btn.setEnabled(True)
    
    def on_load_error(self, error_message):
        """Handle user data load error"""
        MessageBoxes.show_error(
            self,
            "Load Error",
            f"Failed to load users: {error_message}"
        )
        self.update_status("Error loading users")
        self.refresh_btn.setText("Refresh")
        self.refresh_btn.setEnabled(True)
    
    def populate_users_table(self, users):
        """Populate the users table with data"""
        self.users_table.setRowCount(len(users))
        
        for row, user in enumerate(users):
            # ID
            self.users_table.setItem(row, 0, QTableWidgetItem(str(user.get('id', ''))))
            
            # Email
            self.users_table.setItem(row, 1, QTableWidgetItem(user.get('email', '')))
            
            # Name
            self.users_table.setItem(row, 2, QTableWidgetItem(user.get('name', '')))
            
            # Role
            role = user.get('role', 'user')
            role_item = QTableWidgetItem(role.title())
            if role == 'admin':
                role_item.setBackground(Qt.yellow)
            self.users_table.setItem(row, 3, role_item)
            
            # Status
            is_locked = user.get('is_locked', 0)
            status = "Locked" if is_locked else "Active"
            status_item = QTableWidgetItem(status)
            if is_locked:
                status_item.setBackground(Qt.red)
                status_item.setForeground(Qt.white)
            else:
                status_item.setBackground(Qt.green)
                status_item.setForeground(Qt.white)
            self.users_table.setItem(row, 4, status_item)
            
            # Created At
            created_at = user.get('created_at', '')
            if created_at:
                created_at = created_at.split(' ')[0]  # Show only date
            self.users_table.setItem(row, 5, QTableWidgetItem(created_at))
            
            # Last Login (placeholder for now)
            self.users_table.setItem(row, 6, QTableWidgetItem("N/A"))
        
        # Sort by ID initially
        self.users_table.sortItems(0, Qt.AscendingOrder)
    
    def filter_users(self):
        """Filter users based on search input"""
        search_text = self.search_input.text().lower()
        
        if not search_text:
            # Show all users
            filtered_users = self.users_data
        else:
            # Filter users by email or name
            filtered_users = []
            for user in self.users_data:
                email = user.get('email', '').lower()
                name = user.get('name', '').lower()
                if search_text in email or search_text in name:
                    filtered_users.append(user)
        
        self.populate_users_table(filtered_users)
        self.update_status(f"Showing {len(filtered_users)} of {len(self.users_data)} users")
    
    def on_user_selection_changed(self):
        """Handle user selection change"""
        selected_items = self.users_table.selectedItems()
        has_selection = bool(selected_items)
        
        # Enable/disable action buttons
        self.lock_btn.setEnabled(has_selection)
        self.unlock_btn.setEnabled(has_selection)
        self.delete_btn.setEnabled(has_selection)
        self.change_role_btn.setEnabled(has_selection)
        
        if selected_items:
            row = selected_items[0].row()
            user_id_item = self.users_table.item(row, 0)
            if user_id_item:
                try:
                    user_id = int(user_id_item.text())
                    self.user_selected.emit(user_id)
                    
                    # Update button states based on user status
                    user = self.get_selected_user()
                    if user:
                        is_locked = user.get('is_locked', 0)
                        current_user_id = session_manager.get_user_id()
                        is_self = user.get('id') == current_user_id
                        
                        # Disable dangerous actions on self
                        self.lock_btn.setEnabled(not is_self and not is_locked)
                        self.unlock_btn.setEnabled(not is_self and is_locked)
                        self.delete_btn.setEnabled(not is_self)
                        
                except ValueError:
                    pass
    
    def get_selected_user(self):
        """Get currently selected user data"""
        selected_items = self.users_table.selectedItems()
        if not selected_items:
            return None
        
        row = selected_items[0].row()
        user_id_item = self.users_table.item(row, 0)
        if not user_id_item:
            return None
        
        try:
            user_id = int(user_id_item.text())
            # Find user in data
            for user in self.users_data:
                if user.get('id') == user_id:
                    return user
        except ValueError:
            pass
        
        return None
    
    def refresh_table(self):
        """Refresh the table data"""
        self.load_users()
    
    def show_context_menu(self, position):
        """Show context menu on table right-click"""
        if not self.users_table.itemAt(position):
            return
        
        selected_user = self.get_selected_user()
        if not selected_user:
            return
        
        current_user_id = session_manager.get_user_id()
        is_self = selected_user.get('id') == current_user_id
        is_locked = selected_user.get('is_locked', 0)
        
        menu = QMenu(self)
        
        # Lock action
        if not is_self and not is_locked:
            lock_action = QAction("Lock User", self)
            lock_action.triggered.connect(self.lock_selected_user)
            menu.addAction(lock_action)
        
        # Unlock action
        if not is_self and is_locked:
            unlock_action = QAction("Unlock User", self)
            unlock_action.triggered.connect(self.unlock_selected_user)
            menu.addAction(unlock_action)
        
        # Change role action
        change_role_action = QAction("Change Role", self)
        change_role_action.triggered.connect(self.change_user_role)
        menu.addAction(change_role_action)
        
        menu.addSeparator()
        
        # Delete action
        if not is_self:
            delete_action = QAction("Delete User", self)
            delete_action.triggered.connect(self.delete_selected_user)
            menu.addAction(delete_action)
        
        if menu.actions():
            menu.exec_(self.users_table.mapToGlobal(position))
    
    def lock_selected_user(self):
        """Lock the selected user account"""
        user = self.get_selected_user()
        if not user:
            return
        
        # Confirm action
        reply = MessageBoxes.show_question(
            self,
            "Confirm Lock User",
            f"Are you sure you want to lock the account for {user.get('email')}?\n\nThis will prevent the user from logging in."
        )
        
        if not reply:
            return
        
        try:
            db = DatabaseManager()
            admin_user_id = session_manager.get_user_id()
            result = db.admin_lock_user_account(user.get('id'), admin_user_id)
            
            if result:
                MessageBoxes.show_info(self, "Success", f"User {user.get('email')} has been locked.")
                self.log_action("user_locked", "success", f"Locked user: {user.get('email')}")
                self.refresh_table()
            else:
                MessageBoxes.show_error(self, "Error", "Failed to lock user account.")
                
        except Exception as e:
            MessageBoxes.show_error(self, "Database Error", f"Failed to lock user: {str(e)}")
    
    def unlock_selected_user(self):
        """Unlock the selected user account"""
        user = self.get_selected_user()
        if not user:
            return
        
        # Confirm action
        reply = MessageBoxes.show_question(
            self,
            "Confirm Unlock User",
            f"Are you sure you want to unlock the account for {user.get('email')}?"
        )
        
        if not reply:
            return
        
        try:
            db = DatabaseManager()
            admin_user_id = session_manager.get_user_id()
            result = db.admin_unlock_user_account(user.get('id'), admin_user_id)
            
            if result:
                MessageBoxes.show_info(self, "Success", f"User {user.get('email')} has been unlocked.")
                self.log_action("user_unlocked", "success", f"Unlocked user: {user.get('email')}")
                self.refresh_table()
            else:
                MessageBoxes.show_error(self, "Error", "Failed to unlock user account.")
                
        except Exception as e:
            MessageBoxes.show_error(self, "Database Error", f"Failed to unlock user: {str(e)}")
    
    def delete_selected_user(self):
        """Delete the selected user account"""
        user = self.get_selected_user()
        if not user:
            return
        
        # Confirm action with strong warning
        reply = MessageBoxes.show_question(
            self,
            "Confirm Delete User",
            f"⚠️ WARNING: This will permanently delete the account for {user.get('email')}!\n\n"
            f"This action cannot be undone and will remove:\n"
            f"• User account and profile\n"
            f"• User's encryption keys\n"
            f"• All associated data\n\n"
            f"Are you absolutely sure you want to proceed?",
            default_yes=False
        )
        
        if not reply:
            return
        
        try:
            db = DatabaseManager()
            admin_user_id = session_manager.get_user_id()
            result = db.admin_delete_user_account(user.get('id'), admin_user_id)
            
            if result:
                MessageBoxes.show_info(self, "Success", f"User {user.get('email')} has been deleted.")
                self.log_action("user_deleted", "success", f"Deleted user: {user.get('email')}")
                self.refresh_table()
            else:
                MessageBoxes.show_error(self, "Error", "Failed to delete user account.")
                
        except Exception as e:
            MessageBoxes.show_error(self, "Database Error", f"Failed to delete user: {str(e)}")
    
    def change_user_role(self):
        """Change the selected user's role"""
        user = self.get_selected_user()
        if not user:
            return
        
        current_role = user.get('role', 'user')
        new_role = 'admin' if current_role == 'user' else 'user'
        
        # Confirm action
        reply = MessageBoxes.show_question(
            self,
            "Confirm Role Change",
            f"Change role for {user.get('email')} from '{current_role}' to '{new_role}'?"
        )
        
        if not reply:
            return
        
        try:
            db = DatabaseManager()
            admin_user_id = session_manager.get_user_id()
            result = db.update_user_role(user.get('id'), new_role, admin_user_id)
            
            if result:
                MessageBoxes.show_info(self, "Success", f"User {user.get('email')} role changed to {new_role}.")
                self.log_action("user_role_changed", "success", f"Changed role for {user.get('email')} to {new_role}")
                self.refresh_table()
            else:
                MessageBoxes.show_error(self, "Error", "Failed to change user role.")
                
        except Exception as e:
            MessageBoxes.show_error(self, "Database Error", f"Failed to change user role: {str(e)}")
    
    def closeEvent(self, event):
        """Handle window close event"""
        self.log_action("user_management_closed", "info", "User management window closed")
        super().closeEvent(event) 
