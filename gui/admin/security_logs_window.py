from PyQt5.QtWidgets import (QVBoxLayout, QHBoxLayout, QTableWidget, 
                             QTableWidgetItem, QLineEdit, QComboBox, 
                             QPushButton, QLabel, QHeaderView)
from PyQt5.QtCore import QThread, pyqtSignal, Qt
from PyQt5.QtGui import QFont, QColor

from ..base import BaseWindow
from ..utils import MessageBoxes
from modules.database import DatabaseManager
from ..app import session_manager


class LogsDataWorker(QThread):
    data_ready = pyqtSignal(list)
    error_occurred = pyqtSignal(str)
    
    def __init__(self, user_filter="", action_filter="", limit=1000):
        super().__init__()
        self.user_filter = user_filter
        self.action_filter = action_filter
        self.limit = limit
    
    def run(self):
        try:
            db = DatabaseManager()
            logs = db.get_system_activity_logs(
                limit=self.limit, 
                user_filter=self.user_filter if self.user_filter else None,
                action_filter=self.action_filter if self.action_filter else None
            )
            self.data_ready.emit(logs)
        except Exception as e:
            self.error_occurred.emit(str(e))


class SecurityLogsWindow(BaseWindow):
    """Security activity logs interface for administrators"""
    
    def __init__(self, parent=None):
        super().__init__("Security Activity Logs - Security Application", parent)
        
        # Check admin access
        if not self.check_admin_access():
            self.close()
            return
            
        self.worker = None
        self.setup_logs_ui()
        self.load_data()
        self.log_action("security_logs_opened", "success", "Security logs window accessed")
    
    def check_admin_access(self) -> bool:
        """Check if current user has admin privileges"""
        if not session_manager.is_fully_authenticated():
            MessageBoxes.show_error(
                self, 
                "Access Denied", 
                "You must be fully authenticated to access security logs."
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
    
    def setup_logs_ui(self):
        """Setup the security logs UI"""
        main_layout = QVBoxLayout(self.central_widget)
        
        # Filter controls
        filter_layout = QHBoxLayout()
        
        # User filter
        filter_layout.addWidget(QLabel("User:"))
        self.user_filter = QLineEdit()
        self.user_filter.setPlaceholderText("Filter by user email...")
        self.user_filter.textChanged.connect(self.on_filter_changed)
        filter_layout.addWidget(self.user_filter)
        
        # Action filter
        filter_layout.addWidget(QLabel("Action:"))
        self.action_filter = QComboBox()
        self.action_filter.addItems([
            "All", "Login", "Logout", "Register", "Key Generated", 
            "File Encrypted", "File Decrypted", "File Signed", 
            "Signature Verified", "User Created", "User Locked", 
            "User Unlocked", "Role Changed"
        ])
        self.action_filter.currentTextChanged.connect(self.on_filter_changed)
        filter_layout.addWidget(self.action_filter)
        
        # Refresh button
        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self.load_data)
        filter_layout.addWidget(self.refresh_btn)
        
        filter_layout.addStretch()
        main_layout.addLayout(filter_layout)
        
        # Logs table
        self.logs_table = QTableWidget()
        self.logs_table.setColumnCount(7)
        self.logs_table.setHorizontalHeaderLabels([
            "ID", "Timestamp", "User Email", "Action", "Status", "Details", "IP Address"
        ])
        
        # Hide ID column
        self.logs_table.setColumnHidden(0, True)
        
        # Configure table
        self.logs_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.logs_table.setAlternatingRowColors(True)
        self.logs_table.setSortingEnabled(True)
        
        # Auto-resize columns
        header = self.logs_table.horizontalHeader()
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)  # Timestamp
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)  # User Email
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)  # Action
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)  # Status
        header.setSectionResizeMode(5, QHeaderView.Stretch)          # Details
        header.setSectionResizeMode(6, QHeaderView.ResizeToContents)  # IP Address
        
        main_layout.addWidget(self.logs_table)
        
        # Status label
        self.status_label = QLabel("Ready")
        main_layout.addWidget(self.status_label)
        
        self.apply_professional_styling()
    
    def apply_professional_styling(self):
        self.setStyleSheet("""
            QLineEdit, QComboBox, QPushButton {
                font-size: 11px;
                padding: 8px;
                border: 1px solid #ddd;
                border-radius: 4px;
                background-color: white;
            }
            QPushButton {
                background-color: #f8f9fa;
                min-width: 80px;
            }
            QPushButton:hover {
                background-color: #e9ecef;
            }
            QTableWidget {
                gridline-color: #e0e0e0;
                font-size: 11px;
                background-color: white;
            }
            QTableWidget::item {
                padding: 8px;
                border-bottom: 1px solid #f0f0f0;
            }
            QTableWidget::item:selected {
                background-color: #007bff;
                color: white;
            }
            QHeaderView::section {
                background-color: #f8f9fa;
                padding: 8px;
                border: none;
                border-bottom: 2px solid #e9ecef;
                font-weight: bold;
                font-size: 11px;
            }
            QLabel {
                font-size: 11px;
                color: #495057;
            }
        """)
    
    def on_filter_changed(self):
        # Reload data when filters change
        self.load_data()
    
    def load_data(self):
        if self.worker and self.worker.isRunning():
            return
            
        self.status_label.setText("Loading security logs...")
        self.refresh_btn.setEnabled(False)
        
        user_filter = self.user_filter.text().strip()
        action_filter = self.action_filter.currentText()
        if action_filter == "All":
            action_filter = ""
            
        self.worker = LogsDataWorker(user_filter, action_filter)
        self.worker.data_ready.connect(self.populate_table)
        self.worker.error_occurred.connect(self.handle_error)
        self.worker.finished.connect(self.on_worker_finished)
        self.worker.start()
    
    def populate_table(self, logs):
        self.logs_table.setRowCount(len(logs))
        
        for row, log in enumerate(logs):
            # ID (hidden)
            self.logs_table.setItem(row, 0, QTableWidgetItem(str(log[0])))
            
            # Timestamp
            timestamp_item = QTableWidgetItem(str(log[7]))
            self.logs_table.setItem(row, 1, timestamp_item)
            
            # User Email
            user_email_item = QTableWidgetItem(str(log[2]))
            self.logs_table.setItem(row, 2, user_email_item)
            
            # Action
            action_item = QTableWidgetItem(str(log[3]))
            self.logs_table.setItem(row, 3, action_item)
            
            # Status with color coding
            status_item = QTableWidgetItem(str(log[4]))
            if log[4] == 'Success':
                status_item.setForeground(QColor("#28a745"))
            elif log[4] == 'Failed':
                status_item.setForeground(QColor("#dc3545"))
            elif log[4] == 'Warning':
                status_item.setForeground(QColor("#ffc107"))
            self.logs_table.setItem(row, 4, status_item)
            
            # Details
            details_item = QTableWidgetItem(str(log[5] or ""))
            details_item.setToolTip(str(log[5] or ""))
            self.logs_table.setItem(row, 5, details_item)
            
            # IP Address
            ip_item = QTableWidgetItem(str(log[6] or ""))
            self.logs_table.setItem(row, 6, ip_item)
        
        # Sort by timestamp descending (newest first)
        self.logs_table.sortItems(1, Qt.DescendingOrder)
        
        self.status_label.setText(f"Loaded {len(logs)} log entries")
    
    def handle_error(self, error_message):
        MessageBoxes.show_error("Database Error", f"Failed to load security logs: {error_message}")
        self.status_label.setText("Error loading logs")
    
    def on_worker_finished(self):
        self.refresh_btn.setEnabled(True)
        if self.worker:
            self.worker = None 
