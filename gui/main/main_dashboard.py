from PyQt5.QtWidgets import (QVBoxLayout, QHBoxLayout, QGridLayout, QPushButton, 
                            QLabel, QWidget, QScrollArea, QFrame, QSpacerItem, QSizePolicy)
from PyQt5.QtCore import pyqtSignal, Qt
from PyQt5.QtGui import QFont

from ..base.base_window import BaseWindow
from .feature_card import FeatureCard
from .user_status_widget import UserStatusWidget

class MainDashboard(BaseWindow):
    featureSelected = pyqtSignal(str)
    logoutRequested = pyqtSignal()
    
    def __init__(self, session_manager, parent=None):
        super().__init__(parent)
        self.session_manager = session_manager
        self.setupUI()
        
    def setupUI(self):
        self.setWindowTitle("Security Application - Dashboard")
        self.setMinimumSize(1000, 700)
        
        main_widget = QWidget()
        layout = QVBoxLayout(main_widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        
        header_widget = self.createHeader()
        content_widget = self.createContent()
        
        layout.addWidget(header_widget)
        layout.addWidget(content_widget)
        
        self.setCentralWidget(main_widget)
        
    def createHeader(self):
        header_frame = QFrame()
        header_layout = QHBoxLayout(header_frame)
        header_layout.setContentsMargins(0, 0, 0, 0)
        
        status_widget = UserStatusWidget(self.session_manager)
        
        logout_btn = QPushButton("Logout")
        logout_btn.setFixedSize(80, 35)
        logout_btn.clicked.connect(self.logoutRequested.emit)
        logout_btn.setStyleSheet("""
            QPushButton {
                background-color: #e74c3c;
                color: white;
                border: none;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #c0392b;
            }
        """)
        
        header_layout.addWidget(status_widget)
        header_layout.addWidget(logout_btn)
        
        header_frame.setFixedHeight(70)
        return header_frame
        
    def createContent(self):
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        
        content_widget = QWidget()
        layout = QVBoxLayout(content_widget)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(20)
        
        title_label = QLabel("Security Features Dashboard")
        title_font = QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setStyleSheet("color: #2c3e50; margin-bottom: 10px;")
        
        features_grid = self.createFeaturesGrid()
        
        layout.addWidget(title_label)
        layout.addWidget(features_grid)
        layout.addStretch()
        
        scroll_area.setWidget(content_widget)
        return scroll_area
        
    def createFeaturesGrid(self):
        grid_widget = QWidget()
        grid_layout = QGridLayout(grid_widget)
        grid_layout.setSpacing(15)
        grid_layout.setAlignment(Qt.AlignCenter)
        
        features = self.getFeatureDefinitions()
        
        row, col = 0, 0
        for feature in features:
            card = FeatureCard(
                feature['id'], 
                feature['title'], 
                feature['description']
            )
            card.clicked.connect(self.featureSelected.emit)
            
            grid_layout.addWidget(card, row, col)
            
            col += 1
            if col >= 4:
                col = 0
                row += 1
                
        return grid_widget
        
    def getFeatureDefinitions(self):
        return [
            {'id': 'register', 'title': 'User Registration', 'description': 'Register new user account'},
            {'id': 'profile', 'title': 'Profile Management', 'description': 'Manage user profile and settings'},
            {'id': 'mfa', 'title': 'Multi-Factor Auth', 'description': 'Configure MFA settings'},
            {'id': 'recovery', 'title': 'Account Recovery', 'description': 'Recover account access'},
            
            {'id': 'encrypt', 'title': 'File Encryption', 'description': 'Encrypt files for secure storage'},
            {'id': 'decrypt', 'title': 'File Decryption', 'description': 'Decrypt encrypted files'},
            {'id': 'largefile', 'title': 'Large File Handling', 'description': 'Handle files larger than 5MB'},
            {'id': 'formats', 'title': 'File Formats', 'description': 'Choose encryption file formats'},
            
            {'id': 'sign', 'title': 'Digital Signature', 'description': 'Sign files with digital signature'},
            {'id': 'verify', 'title': 'Verify Signature', 'description': 'Verify digital signatures'},
            
            {'id': 'keygen', 'title': 'Generate Keys', 'description': 'Generate new RSA key pairs'},
            {'id': 'keystatus', 'title': 'Key Status', 'description': 'Check key expiration status'},
            {'id': 'keylifecycle', 'title': 'Key Lifecycle', 'description': 'Manage key lifecycle and renewal'},
            {'id': 'keysearch', 'title': 'Search Public Keys', 'description': 'Find public keys by email'},
            
            {'id': 'qrgenerate', 'title': 'Generate QR Code', 'description': 'Create QR codes for public keys'},
            {'id': 'qrscan', 'title': 'Scan QR Code', 'description': 'Import keys from QR codes'},
            
            {'id': 'admin', 'title': 'Admin Panel', 'description': 'Administrative user management'},
            {'id': 'logs', 'title': 'Security Logs', 'description': 'View system security logs'},
        ] 
