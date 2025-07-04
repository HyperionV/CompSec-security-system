"""
System Statistics Window
Dashboard for displaying system-wide statistics and metrics
"""

from PyQt5.QtWidgets import (QVBoxLayout, QHBoxLayout, QGridLayout, QLabel, 
                            QPushButton, QFrame, QScrollArea, QWidget)
from PyQt5.QtCore import pyqtSignal, Qt, QThread, pyqtSignal as Signal
from PyQt5.QtGui import QFont

from ..base.base_window import BaseWindow
from ..app import session_manager
from ..utils.message_boxes import MessageBoxes
from modules.database import DatabaseManager

class StatisticsWorker(QThread):
    """Worker thread for loading statistics data"""
    data_loaded = Signal(dict)
    error_occurred = Signal(str)
    
    def run(self):
        try:
            db = DatabaseManager()
            stats = db.get_system_statistics()
            self.data_loaded.emit(stats)
        except Exception as e:
            self.error_occurred.emit(str(e))

class StatisticCard(QFrame):
    """Individual statistic card for displaying metrics"""
    
    def __init__(self, title, value, description="", icon_color="#007acc"):
        super().__init__()
        self.setup_ui(title, value, description, icon_color)
    
    def setup_ui(self, title, value, description, icon_color):
        """Setup the statistic card UI"""
        self.setFixedSize(200, 120)
        self.setStyleSheet(f"""
            QFrame {{
                background-color: white;
                border: 1px solid #ddd;
                border-radius: 8px;
                margin: 5px;
            }}
            QFrame:hover {{
                border-color: {icon_color};
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }}
        """)
        
        layout = QVBoxLayout(self)
        layout.setSpacing(5)
        layout.setContentsMargins(15, 10, 15, 10)
        
        # Title
        title_label = QLabel(title)
        title_font = QFont()
        title_font.setPointSize(9)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setStyleSheet(f"color: {icon_color}; margin-bottom: 5px;")
        title_label.setWordWrap(True)
        
        # Value
        value_label = QLabel(str(value))
        value_font = QFont()
        value_font.setPointSize(24)
        value_font.setBold(True)
        value_label.setFont(value_font)
        value_label.setStyleSheet("color: #333; margin: 5px 0;")
        value_label.setAlignment(Qt.AlignCenter)
        
        # Description
        desc_label = QLabel(description)
        desc_font = QFont()
        desc_font.setPointSize(8)
        desc_label.setFont(desc_font)
        desc_label.setStyleSheet("color: #666;")
        desc_label.setWordWrap(True)
        desc_label.setAlignment(Qt.AlignCenter)
        
        layout.addWidget(title_label)
        layout.addWidget(value_label)
        layout.addWidget(desc_label)
        layout.addStretch()
    
    def update_value(self, new_value):
        """Update the displayed value"""
        # Find the value label (second widget) and update it
        layout = self.layout()
        if layout.count() >= 2:
            value_label = layout.itemAt(1).widget()
            if isinstance(value_label, QLabel):
                value_label.setText(str(new_value))

class SystemStatisticsWindow(BaseWindow):
    """System statistics dashboard for administrators"""
    
    def __init__(self, parent=None):
        super().__init__("System Statistics - Security Application", parent)
        
        # Check admin access
        if not self.check_admin_access():
            self.close()
            return
            
        self.stats_data = {}
        self.stat_cards = {}
        self.setup_statistics_ui()
        self.load_statistics()
        self.log_action("system_statistics_opened", "success", "System statistics window accessed")
    
    def check_admin_access(self) -> bool:
        """Check if current user has admin privileges"""
        if not session_manager.is_fully_authenticated():
            MessageBoxes.show_error(
                self, 
                "Access Denied", 
                "You must be fully authenticated to access system statistics."
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
    
    def setup_statistics_ui(self):
        """Setup the statistics dashboard UI"""
        # Header section
        header_layout = QHBoxLayout()
        
        # Title
        title_label = QLabel("System Statistics Dashboard")
        title_font = QFont()
        title_font.setPointSize(18)
        title_font.setBold(True)
        title_label.setFont(title_font)
        
        # Refresh button
        self.refresh_btn = QPushButton("Refresh Statistics")
        self.refresh_btn.clicked.connect(self.load_statistics)
        self.refresh_btn.setStyleSheet("""
            QPushButton {
                background-color: #007acc;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 5px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #005a9e;
            }
        """)
        
        header_layout.addWidget(title_label)
        header_layout.addStretch()
        header_layout.addWidget(self.refresh_btn)
        
        # Statistics grid
        stats_scroll = QScrollArea()
        stats_widget = QWidget()
        self.stats_layout = QGridLayout(stats_widget)
        self.stats_layout.setSpacing(15)
        
        # Create statistic cards
        self.create_statistic_cards()
        
        stats_scroll.setWidget(stats_widget)
        stats_scroll.setWidgetResizable(True)
        stats_scroll.setStyleSheet("""
            QScrollArea {
                border: none;
                background-color: #f8f9fa;
            }
        """)
        
        # Main layout
        self.main_layout.addLayout(header_layout)
        self.main_layout.addWidget(stats_scroll)
        
        self.update_status("Ready - Click Refresh to load latest statistics")
    
    def create_statistic_cards(self):
        """Create all statistic cards"""
        # User Statistics
        self.stat_cards['total_users'] = StatisticCard(
            "Total Users", 
            "0", 
            "Registered accounts",
            "#007acc"
        )
        
        self.stat_cards['admin_users'] = StatisticCard(
            "Admin Users", 
            "0", 
            "Administrator accounts",
            "#dc3545"
        )
        
        self.stat_cards['locked_accounts'] = StatisticCard(
            "Locked Accounts", 
            "0", 
            "Currently locked users",
            "#ffc107"
        )
        
        self.stat_cards['recent_registrations'] = StatisticCard(
            "Recent Registrations", 
            "0", 
            "New users (30 days)",
            "#28a745"
        )
        
        # Key Statistics
        self.stat_cards['total_keys'] = StatisticCard(
            "Total RSA Keys", 
            "0", 
            "All key pairs generated",
            "#6f42c1"
        )
        
        self.stat_cards['valid_keys'] = StatisticCard(
            "Valid Keys", 
            "0", 
            "Currently active keys",
            "#20c997"
        )
        
        self.stat_cards['expired_keys'] = StatisticCard(
            "Expired Keys", 
            "0", 
            "Keys past expiration",
            "#fd7e14"
        )
        
        self.stat_cards['imported_keys'] = StatisticCard(
            "Imported Keys", 
            "0", 
            "Public keys imported",
            "#6610f2"
        )
        
        # Add cards to grid layout (2 columns, 4 rows)
        row = 0
        col = 0
        for card in self.stat_cards.values():
            self.stats_layout.addWidget(card, row, col)
            col += 1
            if col >= 4:  # 4 cards per row
                col = 0
                row += 1
        
        # Add stretch to center the cards
        self.stats_layout.setRowStretch(row + 1, 1)
    
    def load_statistics(self):
        """Load statistics from database"""
        self.update_status("Loading statistics...")
        self.refresh_btn.setText("Loading...")
        self.refresh_btn.setEnabled(False)
        
        # Create and start worker thread
        self.worker = StatisticsWorker()
        self.worker.data_loaded.connect(self.on_statistics_loaded)
        self.worker.error_occurred.connect(self.on_load_error)
        self.worker.start()
    
    def on_statistics_loaded(self, stats):
        """Handle successful statistics load"""
        self.stats_data = stats
        self.update_statistic_cards(stats)
        self.update_status(f"Statistics updated - {len(stats)} metrics loaded")
        self.refresh_btn.setText("Refresh Statistics")
        self.refresh_btn.setEnabled(True)
    
    def on_load_error(self, error_message):
        """Handle statistics load error"""
        MessageBoxes.show_error(
            self,
            "Load Error",
            f"Failed to load statistics: {error_message}"
        )
        self.update_status("Error loading statistics")
        self.refresh_btn.setText("Refresh Statistics")
        self.refresh_btn.setEnabled(True)
    
    def update_statistic_cards(self, stats):
        """Update all statistic cards with new data"""
        # Update each card with corresponding data
        card_mapping = {
            'total_users': stats.get('total_users', 0),
            'admin_users': stats.get('admin_users', 0),
            'locked_accounts': stats.get('locked_accounts', 0),
            'recent_registrations': stats.get('recent_registrations', 0),
            'total_keys': stats.get('total_keys', 0),
            'valid_keys': stats.get('valid_keys', 0),
            'expired_keys': stats.get('expired_keys', 0),
            'imported_keys': stats.get('imported_keys', 0)
        }
        
        for card_name, value in card_mapping.items():
            if card_name in self.stat_cards:
                self.stat_cards[card_name].update_value(value)
    
    def get_statistics_summary(self):
        """Get a summary of current statistics"""
        if not self.stats_data:
            return "No statistics loaded"
        
        total_users = self.stats_data.get('total_users', 0)
        active_keys = self.stats_data.get('valid_keys', 0)
        locked_accounts = self.stats_data.get('locked_accounts', 0)
        
        return f"Total Users: {total_users}, Active Keys: {active_keys}, Locked: {locked_accounts}"
    
    def closeEvent(self, event):
        """Handle window close event"""
        self.log_action("system_statistics_closed", "info", "System statistics window closed")
        super().closeEvent(event) 
