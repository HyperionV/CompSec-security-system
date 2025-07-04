"""
Admin Dashboard Window
Provides administrative interface for system management
"""

from PyQt5.QtWidgets import (QVBoxLayout, QHBoxLayout, QGridLayout, QLabel, 
                            QPushButton, QFrame, QScrollArea, QWidget)
from PyQt5.QtCore import pyqtSignal, Qt
from PyQt5.QtGui import QFont

from ..base.base_window import BaseWindow
from ..app import session_manager
from ..utils.message_boxes import MessageBoxes

class AdminFeatureCard(QFrame):
    """Individual feature card for admin functions"""
    
    clicked = pyqtSignal(str)
    
    def __init__(self, feature_id, title, description, icon_text="🔧"):
        super().__init__()
        self.feature_id = feature_id
        self.setup_ui(title, description, icon_text)
    
    def setup_ui(self, title, description, icon_text):
        """Setup the card UI"""
        self.setFrameStyle(QFrame.Box)
        self.setStyleSheet("""
            QFrame {
                border: 2px solid #ddd;
                border-radius: 8px;
                background-color: #f9f9f9;
                padding: 10px;
            }
            QFrame:hover {
                border-color: #007acc;
                background-color: #f0f8ff;
            }
        """)
        
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        
        # Icon
        icon_label = QLabel(icon_text)
        icon_label.setAlignment(Qt.AlignCenter)
        icon_label.setStyleSheet("font-size: 24px; margin: 5px;")
        
        # Title
        title_label = QLabel(title)
        title_label.setAlignment(Qt.AlignCenter)
        title_font = QFont()
        title_font.setPointSize(12)
        title_font.setBold(True)
        title_label.setFont(title_font)
        
        # Description
        desc_label = QLabel(description)
        desc_label.setAlignment(Qt.AlignCenter)
        desc_label.setWordWrap(True)
        desc_label.setStyleSheet("color: #666; font-size: 10px;")
        
        # Button
        action_btn = QPushButton("Open")
        action_btn.clicked.connect(self.emit_clicked)
        action_btn.setStyleSheet("""
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
        
        layout.addWidget(icon_label)
        layout.addWidget(title_label)
        layout.addWidget(desc_label)
        layout.addWidget(action_btn)
        
        self.setMinimumHeight(160)
        self.setMaximumWidth(200)
    
    def emit_clicked(self):
        """Emit feature selection signal"""
        self.clicked.emit(self.feature_id)

class AdminDashboardWindow(BaseWindow):
    """Admin dashboard for system administration"""
    
    # Signals
    feature_selected = pyqtSignal(str)
    logout_requested = pyqtSignal()
    
    def __init__(self, parent=None):
        super().__init__("Admin Panel - Security Application", parent)
        
        # Check admin access before initializing
        if not self.check_admin_access():
            self.close()
            return
            
        self.setup_admin_ui()
        self.log_action("admin_panel_opened", "success", "Admin panel accessed")
    
    def check_admin_access(self) -> bool:
        """Check if current user has admin privileges"""
        if not session_manager.is_fully_authenticated():
            MessageBoxes.showError(
                self, 
                "Access Denied", 
                "You must be fully authenticated to access admin features."
            )
            return False
        
        if not session_manager.is_admin():
            MessageBoxes.showError(
                self, 
                "Access Denied", 
                "You do not have administrator privileges."
            )
            return False
        
        return True
    
    def setup_admin_ui(self):
        """Setup the admin dashboard UI"""
        # Header
        header_layout = QHBoxLayout()
        
        # Welcome message
        welcome_label = QLabel(f"Administrator Panel")
        welcome_font = QFont()
        welcome_font.setPointSize(16)
        welcome_font.setBold(True)
        welcome_label.setFont(welcome_font)
        
        user_email = session_manager.get_user_email()
        user_label = QLabel(f"Logged in as: {user_email}")
        user_label.setStyleSheet("color: #666; font-size: 12px;")
        
        # Logout button
        logout_btn = QPushButton("Logout")
        logout_btn.clicked.connect(self.handle_logout)
        logout_btn.setStyleSheet("""
            QPushButton {
                background-color: #dc3545;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #c82333;
            }
        """)
        
        header_layout.addWidget(welcome_label)
        header_layout.addWidget(user_label)
        header_layout.addStretch()
        header_layout.addWidget(logout_btn)
        
        # Admin features grid
        scroll_area = QScrollArea()
        scroll_widget = QWidget()
        features_layout = QGridLayout(scroll_widget)
        features_layout.setSpacing(20)
        
        # Admin feature cards
        admin_features = [
            {
                'id': 'user_management',
                'title': 'User Management',
                'description': 'Manage user accounts, roles, and permissions',
                'icon': '👥'
            },
            {
                'id': 'system_statistics',
                'title': 'System Statistics',
                'description': 'View system-wide usage and performance metrics',
                'icon': '📊'
            },
            {
                'id': 'security_logs',
                'title': 'Security Logs',
                'description': 'Monitor system security events and activities',
                'icon': '🔍'
            }
        ]
        
        row, col = 0, 0
        for feature in admin_features:
            card = AdminFeatureCard(
                feature['id'],
                feature['title'], 
                feature['description'],
                feature['icon']
            )
            card.clicked.connect(self.handle_feature_selection)
            features_layout.addWidget(card, row, col)
            
            col += 1
            if col >= 3:  # 3 cards per row
                col = 0
                row += 1
        
        scroll_area.setWidget(scroll_widget)
        scroll_area.setWidgetResizable(True)
        scroll_area.setStyleSheet("border: none;")
        
        # Main layout
        self.main_layout.addLayout(header_layout)
        self.main_layout.addWidget(scroll_area)
        
        self.update_status("Admin panel ready")
    
    def handle_feature_selection(self, feature_id):
        """Handle admin feature selection"""
        self.log_action(f"admin_feature_selected", "info", f"Feature: {feature_id}")
        self.feature_selected.emit(feature_id)
    
    def handle_logout(self):
        """Handle logout request"""
        self.log_action("admin_logout_requested", "info", "Admin logout initiated")
        self.logout_requested.emit()
    
    def closeEvent(self, event):
        """Handle window close event"""
        self.log_action("admin_panel_closed", "info", "Admin panel closed")
        super().closeEvent(event) 
