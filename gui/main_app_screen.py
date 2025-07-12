from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTabWidget, 
                             QLabel, QPushButton, QMenuBar, QAction)
from PyQt5.QtCore import pyqtSignal, Qt
from PyQt5.QtGui import QFont
from .utils.dialogs import show_question

class MainAppScreen(QWidget):
    logout_requested = pyqtSignal()
    
    def __init__(self, user_session, managers, parent=None):
        super().__init__(parent)
        self.user_session = user_session
        self.managers = managers
        self.tab_widgets = {}
        self.setup_ui()
    
    def setup_ui(self):
        layout = QVBoxLayout()
        
        # Header with user info and logout
        header_layout = QHBoxLayout()
        
        # Welcome message
        user_info = self.user_session.user_info
        welcome_label = QLabel(f"Welcome, {user_info['name']} ({user_info['email']})")
        welcome_font = QFont("Arial", 12, QFont.Bold)
        welcome_label.setFont(welcome_font)
        header_layout.addWidget(welcome_label)
        
        header_layout.addStretch()
        
        # Logout button
        self.logout_button = QPushButton("Logout")
        self.logout_button.clicked.connect(self.handle_logout)
        header_layout.addWidget(self.logout_button)
        
        layout.addLayout(header_layout)
        
        # Main tab widget
        self.tab_widget = QTabWidget()
        
        # Add tabs based on user role
        self.add_core_tabs()
        
        # Add admin tab if user is admin
        if user_info.get('role') == 'admin':
            self.add_admin_tab()
        
        layout.addWidget(self.tab_widget)
        self.setLayout(layout)
    
    def add_core_tabs(self):
        """Add core functionality tabs available to all users"""
        # Import tab classes (will be created later)
        from .tabs.qr_operations_tab import QROperationsTab
        from .tabs.key_management_tab import KeyManagementTab
        from .tabs.account_tab import AccountTab
        from .tabs.file_operations_tab import FileOperationsTab
        from .tabs.signature_tab import SignatureTab
        from .tabs.public_keys_tab import PublicKeysTab
        
        # QR Operations
        self.qr_tab = QROperationsTab(self.user_session, self.managers, self)
        self.tab_widget.addTab(self.qr_tab, "QR Operations")
        self.tab_widgets['qr'] = self.qr_tab
        
        # Key Management
        self.key_tab = KeyManagementTab(self.user_session, self.managers, self)
        self.tab_widget.addTab(self.key_tab, "Key Management")
        self.tab_widgets['keys'] = self.key_tab
        
        # Account Settings
        self.account_tab = AccountTab(self.user_session, self.managers, self)
        self.tab_widget.addTab(self.account_tab, "Account Settings")
        self.tab_widgets['account'] = self.account_tab
        
        # File Operations
        self.file_tab = FileOperationsTab(self.user_session, self.managers, self)
        self.tab_widget.addTab(self.file_tab, "File Operations")
        self.tab_widgets['files'] = self.file_tab
        
        # Digital Signatures
        self.signature_tab = SignatureTab(self.user_session, self.managers, self)
        self.tab_widget.addTab(self.signature_tab, "Digital Signatures")
        self.tab_widgets['signatures'] = self.signature_tab
        
        # Public Keys
        self.pubkey_tab = PublicKeysTab(self.user_session, self.managers, self)
        self.tab_widget.addTab(self.pubkey_tab, "Public Keys")
        self.tab_widgets['pubkeys'] = self.pubkey_tab
    
    def add_admin_tab(self):
        """Add admin tab for admin users"""
        from .tabs.admin_tab import AdminTab
        
        self.admin_tab = AdminTab(self.user_session, self.managers, self)
        self.tab_widget.addTab(self.admin_tab, "Admin Panel")
        self.tab_widgets['admin'] = self.admin_tab
    
    def handle_logout(self):
        """Handle logout request"""
        if show_question(self, "Logout", "Are you sure you want to logout?"):
            # Clear global session
            from modules.auth import global_user_session
            global_user_session.clear_current_user()
            
            self.user_session.logout()
            self.logout_requested.emit()
    
    def refresh_all_tabs(self):
        """Refresh data in all tabs"""
        for tab in self.tab_widgets.values():
            if hasattr(tab, 'refresh_data'):
                tab.refresh_data()
    
    def get_current_tab(self):
        """Get currently selected tab"""
        current_index = self.tab_widget.currentIndex()
        return self.tab_widget.widget(current_index)
    
    def switch_to_tab(self, tab_name):
        """Switch to specific tab by name"""
        if tab_name in self.tab_widgets:
            tab_widget = self.tab_widgets[tab_name]
            index = self.tab_widget.indexOf(tab_widget)
            if index >= 0:
                self.tab_widget.setCurrentIndex(index) 