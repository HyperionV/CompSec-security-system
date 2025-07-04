from PyQt5.QtWidgets import QTabWidget, QVBoxLayout, QWidget
from PyQt5.QtCore import Qt
from ..base.base_window import BaseWindow
from .qr_generation_dialog import QRGenerationDialog
from .qr_scan_dialog import QRScanDialog

class QRManagementWindow(BaseWindow):
    def __init__(self, session_manager, parent=None):
        super().__init__(parent)
        self.session_manager = session_manager
        
        self.setWindowTitle("QR Code Management")
        self.setFixedSize(800, 750)
        self.setup_ui()
    
    def setup_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        layout = QVBoxLayout(central_widget)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Create tab widget
        self.tab_widget = QTabWidget()
        self.tab_widget.setTabPosition(QTabWidget.North)
        
        # Create and add tabs
        self.setup_generation_tab()
        self.setup_scanning_tab()
        
        layout.addWidget(self.tab_widget)
        
        # Apply styling
        self.apply_tab_styling()
    
    def setup_generation_tab(self):
        # Create generation dialog content
        self.generation_widget = QRGenerationDialog(self.session_manager)
        
        # Embed in tab
        self.tab_widget.addTab(self.generation_widget, "Generate QR Code")
    
    def setup_scanning_tab(self):
        # Create scanning dialog content
        self.scanning_widget = QRScanDialog(self.session_manager)
        
        # Embed in tab
        self.tab_widget.addTab(self.scanning_widget, "Scan QR Code")
    
    def apply_tab_styling(self):
        self.tab_widget.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #cccccc;
                background-color: white;
                border-radius: 5px;
            }
            
            QTabWidget::tab-bar {
                alignment: center;
            }
            
            QTabBar::tab {
                background-color: #f0f0f0;
                border: 1px solid #cccccc;
                border-bottom: none;
                border-top-left-radius: 5px;
                border-top-right-radius: 5px;
                min-width: 120px;
                padding: 8px 16px;
                margin-right: 2px;
            }
            
            QTabBar::tab:selected {
                background-color: white;
                border-bottom: 1px solid white;
            }
            
            QTabBar::tab:hover:!selected {
                background-color: #e8e8e8;
            }
        """)
    
    def closeEvent(self, event):
        # Close generation dialog properly
        if hasattr(self.generation_widget, 'closeEvent'):
            self.generation_widget.closeEvent(event)
        
        # Close scanning dialog properly  
        if hasattr(self.scanning_widget, 'closeEvent'):
            self.scanning_widget.closeEvent(event)
        
        event.accept() 
