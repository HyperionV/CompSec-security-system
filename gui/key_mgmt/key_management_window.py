from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTabWidget,
                             QTableWidget, QTableWidgetItem, QHeaderView, 
                             QPushButton, QLabel, QGroupBox, QFormLayout, QLineEdit)
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QFont
from ..base import BaseWindow
from ..utils import MessageBoxes
from .key_status_widget import KeyStatusWidget
from .key_generation_dialog import KeyGenerationDialog
from .public_key_search_dialog import PublicKeySearchDialog

class KeyManagementWindow(BaseWindow):
    def __init__(self, session_manager, parent=None):
        super().__init__(parent)
        self.session_manager = session_manager
        self.refresh_timer = QTimer()
        self.refresh_timer.setSingleShot(True)
        self.refresh_timer.timeout.connect(self.refresh_key_status)
        self.setup_ui()
        self.load_initial_data()
    
    def setup_ui(self):
        self.setWindowTitle("Key Management")
        self.setFixedSize(900, 700)
        
        layout = QVBoxLayout()
        self.setLayout(layout)
        
        header = QLabel("RSA Key Management")
        header.setFont(QFont("Arial", 16, QFont.Bold))
        header.setAlignment(Qt.AlignCenter)
        layout.addWidget(header)
        
        self.tab_widget = QTabWidget()
        
        self.my_keys_tab = self.create_my_keys_tab()
        self.public_keys_tab = self.create_public_keys_tab()
        self.key_operations_tab = self.create_key_operations_tab()
        
        self.tab_widget.addTab(self.my_keys_tab, "My Keys")
        self.tab_widget.addTab(self.public_keys_tab, "Public Keys")
        self.tab_widget.addTab(self.key_operations_tab, "Key Operations")
        
        layout.addWidget(self.tab_widget)
        
        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("color: #6c757d; padding: 5px;")
        layout.addWidget(self.status_label)
    
    def create_my_keys_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        summary_group = QGroupBox("Key Status Summary")
        summary_layout = QFormLayout(summary_group)
        
        self.key_status_widget = KeyStatusWidget('unknown', 0)
        self.key_count_label = QLabel("Checking...")
        self.expiry_date_label = QLabel("Loading...")
        
        summary_layout.addRow("Status:", self.key_status_widget)
        summary_layout.addRow("Keys:", self.key_count_label)
        summary_layout.addRow("Expires:", self.expiry_date_label)
        
        layout.addWidget(summary_group)
        
        keys_group = QGroupBox("My RSA Keys")
        keys_layout = QVBoxLayout(keys_group)
        
        self.my_keys_table = QTableWidget()
        self.setup_my_keys_table()
        keys_layout.addWidget(self.my_keys_table)
        
        my_keys_button_layout = QHBoxLayout()
        
        self.generate_key_button = QPushButton("Generate New Key Pair")
        self.generate_key_button.clicked.connect(self.generate_new_key_pair)
        
        self.renew_key_button = QPushButton("Renew Keys")
        self.renew_key_button.clicked.connect(self.renew_keys)
        self.renew_key_button.setEnabled(False)
        
        self.check_status_button = QPushButton("Check Status")
        self.check_status_button.clicked.connect(self.check_key_status)
        
        my_keys_button_layout.addWidget(self.generate_key_button)
        my_keys_button_layout.addWidget(self.renew_key_button)
        my_keys_button_layout.addWidget(self.check_status_button)
        my_keys_button_layout.addStretch()
        
        keys_layout.addLayout(my_keys_button_layout)
        layout.addWidget(keys_group)
        
        return tab
    
    def create_public_keys_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        search_group = QGroupBox("Search Public Keys")
        search_layout = QHBoxLayout(search_group)
        
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Enter email to search for public keys...")
        self.search_input.returnPressed.connect(self.search_public_keys)
        
        self.search_button = QPushButton("Search")
        self.search_button.clicked.connect(self.search_public_keys)
        
        self.advanced_search_button = QPushButton("Advanced Search")
        self.advanced_search_button.clicked.connect(self.open_advanced_search)
        
        search_layout.addWidget(QLabel("Email:"))
        search_layout.addWidget(self.search_input)
        search_layout.addWidget(self.search_button)
        search_layout.addWidget(self.advanced_search_button)
        
        layout.addWidget(search_group)
        
        public_keys_group = QGroupBox("Available Public Keys")
        public_keys_layout = QVBoxLayout(public_keys_group)
        
        self.public_keys_table = QTableWidget()
        self.setup_public_keys_table()
        public_keys_layout.addWidget(self.public_keys_table)
        
        self.public_keys_info = QLabel("Loading public keys...")
        self.public_keys_info.setAlignment(Qt.AlignCenter)
        self.public_keys_info.setStyleSheet("color: #6c757d; font-style: italic;")
        public_keys_layout.addWidget(self.public_keys_info)
        
        layout.addWidget(public_keys_group)
        
        return tab
    
    def create_key_operations_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        import_export_group = QGroupBox("Import/Export Operations")
        import_export_layout = QVBoxLayout(import_export_group)
        
        import_layout = QHBoxLayout()
        self.import_key_button = QPushButton("Import Public Key")
        self.import_key_button.clicked.connect(self.import_public_key)
        
        self.import_qr_button = QPushButton("Import from QR Code")
        self.import_qr_button.clicked.connect(self.import_from_qr)
        
        import_layout.addWidget(QLabel("Import:"))
        import_layout.addWidget(self.import_key_button)
        import_layout.addWidget(self.import_qr_button)
        import_layout.addStretch()
        
        import_export_layout.addLayout(import_layout)
        
        export_layout = QHBoxLayout()
        self.export_public_button = QPushButton("Export My Public Key")
        self.export_public_button.clicked.connect(self.export_public_key)
        
        self.export_qr_button = QPushButton("Export as QR Code")
        self.export_qr_button.clicked.connect(self.export_as_qr)
        
        export_layout.addWidget(QLabel("Export:"))
        export_layout.addWidget(self.export_public_button)
        export_layout.addWidget(self.export_qr_button)
        export_layout.addStretch()
        
        import_export_layout.addLayout(export_layout)
        layout.addWidget(import_export_group)
        
        backup_group = QGroupBox("Backup & Restore")
        backup_layout = QVBoxLayout(backup_group)
        
        backup_button_layout = QHBoxLayout()
        self.backup_keys_button = QPushButton("Backup Keys")
        self.backup_keys_button.clicked.connect(self.backup_keys)
        
        self.restore_keys_button = QPushButton("Restore Keys")
        self.restore_keys_button.clicked.connect(self.restore_keys)
        
        backup_button_layout.addWidget(self.backup_keys_button)
        backup_button_layout.addWidget(self.restore_keys_button)
        backup_button_layout.addStretch()
        
        backup_layout.addLayout(backup_button_layout)
        layout.addWidget(backup_group)
        
        layout.addStretch()
        return tab
    
    def setup_my_keys_table(self):
        self.my_keys_table.setColumnCount(4)
        self.my_keys_table.setHorizontalHeaderLabels([
            "Key ID", "Status", "Created Date", "Expiry Date"
        ])
        
        header = self.my_keys_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        header.setSectionResizeMode(1, QHeaderView.Fixed)
        header.setSectionResizeMode(2, QHeaderView.Fixed)
        header.setSectionResizeMode(3, QHeaderView.Fixed)
        
        self.my_keys_table.setColumnWidth(1, 120)
        self.my_keys_table.setColumnWidth(2, 120)
        self.my_keys_table.setColumnWidth(3, 120)
        
        self.my_keys_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.my_keys_table.setAlternatingRowColors(True)
        self.my_keys_table.setSortingEnabled(True)
    
    def setup_public_keys_table(self):
        self.public_keys_table.setColumnCount(5)
        self.public_keys_table.setHorizontalHeaderLabels([
            "Email", "Status", "Created Date", "Expiry Date", "Source"
        ])
        
        header = self.public_keys_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        header.setSectionResizeMode(1, QHeaderView.Fixed)
        header.setSectionResizeMode(2, QHeaderView.Fixed)
        header.setSectionResizeMode(3, QHeaderView.Fixed)
        header.setSectionResizeMode(4, QHeaderView.Fixed)
        
        self.public_keys_table.setColumnWidth(1, 120)
        self.public_keys_table.setColumnWidth(2, 100)
        self.public_keys_table.setColumnWidth(3, 100)
        self.public_keys_table.setColumnWidth(4, 80)
        
        self.public_keys_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.public_keys_table.setAlternatingRowColors(True)
        self.public_keys_table.setSortingEnabled(True)
    
    def load_initial_data(self):
        self.load_my_keys()
        self.load_public_keys()
        self.check_key_status()
    
    def load_my_keys(self):
        try:
            if not self.session_manager.key_manager:
                self.my_keys_table.setRowCount(0)
                self.key_count_label.setText("No key manager available")
                return
            
            success, message, key_data = self.session_manager.key_manager.check_key_status(
                self.session_manager.current_user['id']
            )
            
            self.my_keys_table.setRowCount(0)
            
            if success and key_data:
                row = self.my_keys_table.rowCount()
                self.my_keys_table.insertRow(row)
                
                key_id_item = QTableWidgetItem(f"Key #{key_data.get('key_id', 'Unknown')}")
                self.my_keys_table.setItem(row, 0, key_id_item)
                
                status = key_data.get('status', 'unknown')
                days_remaining = key_data.get('days_remaining', 0)
                status_widget = KeyStatusWidget(status, days_remaining)
                self.my_keys_table.setCellWidget(row, 1, status_widget)
                
                created_item = QTableWidgetItem(key_data.get('created_at', 'Unknown'))
                expires_item = QTableWidgetItem(key_data.get('expires_at', 'Unknown'))
                
                self.my_keys_table.setItem(row, 2, created_item)
                self.my_keys_table.setItem(row, 3, expires_item)
                
                self.renew_key_button.setEnabled(status in ['expiring_soon', 'expired'])
                
                self.key_count_label.setText("1 key pair")
                self.expiry_date_label.setText(key_data.get('expires_at', 'Unknown'))
                
            else:
                self.key_count_label.setText("No keys found")
                self.expiry_date_label.setText("N/A")
                self.renew_key_button.setEnabled(False)
                
        except Exception as e:
            MessageBoxes.show_error(self, "Load Error", f"Failed to load keys: {str(e)}")
    
    def load_public_keys(self):
        try:
            if not hasattr(self.session_manager, 'public_key_manager'):
                from modules.public_key_manager import PublicKeyManager
                self.session_manager.public_key_manager = PublicKeyManager(
                    self.session_manager.current_user['email'],
                    self.session_manager.database,
                    self.session_manager.logger
                )
            
            success, results = self.session_manager.public_key_manager.get_all_available_keys()
            
            if success:
                self.populate_public_keys_table(results)
                count = len(results)
                self.public_keys_info.setText(f"Showing {count} available public key(s)")
                self.public_keys_info.setStyleSheet("color: #007bff;")
            else:
                self.public_keys_info.setText(f"Failed to load keys: {results}")
                self.public_keys_info.setStyleSheet("color: #dc3545;")
                
        except Exception as e:
            self.public_keys_info.setText(f"Error loading public keys: {str(e)}")
            self.public_keys_info.setStyleSheet("color: #dc3545;")
    
    def populate_public_keys_table(self, results):
        self.public_keys_table.setRowCount(0)
        
        for result in results:
            try:
                display_info = self.session_manager.public_key_manager.format_key_display(result)
                
                row = self.public_keys_table.rowCount()
                self.public_keys_table.insertRow(row)
                
                email_item = QTableWidgetItem(display_info['email'])
                self.public_keys_table.setItem(row, 0, email_item)
                
                status_widget = KeyStatusWidget(
                    display_info['status'], 
                    display_info['days_remaining']
                )
                self.public_keys_table.setCellWidget(row, 1, status_widget)
                
                created_item = QTableWidgetItem(display_info['created_date'])
                expiry_item = QTableWidgetItem(display_info['expiry_date'])
                source_item = QTableWidgetItem(display_info['source'].replace('_', ' ').title())
                
                self.public_keys_table.setItem(row, 2, created_item)
                self.public_keys_table.setItem(row, 3, expiry_item)
                self.public_keys_table.setItem(row, 4, source_item)
                
            except Exception as e:
                print(f"Error populating public key row: {e}")
                continue
    
    def generate_new_key_pair(self):
        if not self.session_manager.key_manager:
            MessageBoxes.warning(self, "Key Manager", "Key manager not available.")
            return
        
        dialog = KeyGenerationDialog(
            self.session_manager.key_manager,
            self.session_manager.current_user['id'],
            self
        )
        
        if dialog.exec_() == dialog.Accepted:
            self.load_my_keys()
            self.status_label.setText("Key pair generated successfully")
    
    def renew_keys(self):
        result = MessageBoxes.question(
            self,
            "Renew Keys",
            "Are you sure you want to renew your RSA key pair?\n\n"
            "This will generate new keys and require your passphrase."
        )
        
        if result:
            self.generate_new_key_pair()
    
    def check_key_status(self):
        self.load_my_keys()
        self.refresh_timer.start(30000)
        self.status_label.setText("Key status updated")
    
    def refresh_key_status(self):
        self.load_my_keys()
        self.refresh_timer.start(30000)
    
    def search_public_keys(self):
        email = self.search_input.text().strip()
        if not email:
            MessageBoxes.warning(self, "Search", "Please enter an email address to search.")
            return
        
        try:
            success, results = self.session_manager.public_key_manager.search_keys_by_email(email)
            
            if success:
                self.populate_public_keys_table(results)
                count = len(results)
                self.public_keys_info.setText(f"Found {count} key(s) for '{email}'")
                self.public_keys_info.setStyleSheet("color: #28a745;" if count > 0 else "color: #ffc107;")
            else:
                self.public_keys_info.setText(f"Search failed: {results}")
                self.public_keys_info.setStyleSheet("color: #dc3545;")
                
        except Exception as e:
            MessageBoxes.show_error(self, "Search Error", f"Failed to search: {str(e)}")
    
    def open_advanced_search(self):
        if not hasattr(self.session_manager, 'public_key_manager'):
            MessageBoxes.warning(self, "Search", "Public key manager not available.")
            return
        
        dialog = PublicKeySearchDialog(
            self.session_manager.public_key_manager,
            self
        )
        
        if dialog.exec_() == dialog.Accepted:
            self.load_public_keys()
    
    def import_public_key(self):
        MessageBoxes.information(self, "Import", "Public key import functionality - to be implemented")
    
    def import_from_qr(self):
        MessageBoxes.information(self, "Import QR", "QR code import functionality - to be implemented")
    
    def export_public_key(self):
        MessageBoxes.information(self, "Export", "Public key export functionality - to be implemented")
    
    def export_as_qr(self):
        MessageBoxes.information(self, "Export QR", "QR code export functionality - to be implemented")
    
    def backup_keys(self):
        MessageBoxes.information(self, "Backup", "Key backup functionality - to be implemented")
    
    def restore_keys(self):
        MessageBoxes.information(self, "Restore", "Key restore functionality - to be implemented")
    
    def show_my_keys_tab(self):
        self.tab_widget.setCurrentIndex(0)
    
    def show_public_keys_tab(self):
        self.tab_widget.setCurrentIndex(1)
    
    def show_key_operations_tab(self):
        self.tab_widget.setCurrentIndex(2) 
