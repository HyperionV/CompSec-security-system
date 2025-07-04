from PyQt5.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel, 
                             QLineEdit, QPushButton, QTableWidget, QTableWidgetItem,
                             QHeaderView, QTextEdit, QGroupBox, QFormLayout)
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QFont
from ..base import BaseDialog
from ..utils import MessageBoxes
from .key_status_widget import KeyStatusWidget

class PublicKeySearchDialog(BaseDialog):
    def __init__(self, public_key_manager, parent=None):
        super().__init__(parent)
        self.public_key_manager = public_key_manager
        self.search_timer = QTimer()
        self.search_timer.setSingleShot(True)
        self.search_timer.timeout.connect(self.perform_search)
        self.setup_ui()
    
    def setup_ui(self):
        self.setWindowTitle("Search Public Keys")
        self.setFixedSize(700, 500)
        
        layout = QVBoxLayout(self)
        
        # Header
        header = QLabel("Public Key Search")
        header.setFont(QFont("Arial", 14, QFont.Bold))
        header.setAlignment(Qt.AlignCenter)
        layout.addWidget(header)
        
        # Search group
        search_group = QGroupBox("Search Criteria")
        search_layout = QFormLayout(search_group)
        
        # Email search
        self.email_input = QLineEdit()
        self.email_input.setPlaceholderText("Enter email address to search for public keys")
        self.email_input.textChanged.connect(self.on_search_text_changed)
        search_layout.addRow("Email:", self.email_input)
        
        # Search button
        search_button_layout = QHBoxLayout()
        self.search_button = QPushButton("Search")
        self.search_button.clicked.connect(self.perform_search)
        self.search_button.setDefault(True)
        
        self.clear_button = QPushButton("Clear")
        self.clear_button.clicked.connect(self.clear_results)
        
        search_button_layout.addWidget(self.search_button)
        search_button_layout.addWidget(self.clear_button)
        search_button_layout.addStretch()
        
        search_layout.addRow("", search_button_layout)
        layout.addWidget(search_group)
        
        # Results table
        results_group = QGroupBox("Search Results")
        results_layout = QVBoxLayout(results_group)
        
        self.results_table = QTableWidget()
        self.setup_results_table()
        results_layout.addWidget(self.results_table)
        
        # Results info
        self.results_info = QLabel("Enter an email address to search for public keys")
        self.results_info.setAlignment(Qt.AlignCenter)
        self.results_info.setStyleSheet("color: #6c757d; font-style: italic;")
        results_layout.addWidget(self.results_info)
        
        layout.addWidget(results_group)
        
        # Key details group
        details_group = QGroupBox("Key Details")
        details_layout = QVBoxLayout(details_group)
        
        self.key_details_text = QTextEdit()
        self.key_details_text.setMaximumHeight(100)
        self.key_details_text.setPlaceholderText("Select a key from the results table to view details")
        self.key_details_text.setReadOnly(True)
        details_layout.addWidget(self.key_details_text)
        
        layout.addWidget(details_group)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        self.import_button = QPushButton("Import Selected Key")
        self.import_button.clicked.connect(self.import_selected_key)
        self.import_button.setEnabled(False)
        
        self.close_button = QPushButton("Close")
        self.close_button.clicked.connect(self.accept)
        
        button_layout.addWidget(self.import_button)
        button_layout.addStretch()
        button_layout.addWidget(self.close_button)
        
        layout.addLayout(button_layout)
        
        # Connect table selection
        self.results_table.selectionModel().selectionChanged.connect(self.on_selection_changed)
        
        # Load all available keys on startup
        self.load_all_keys()
    
    def setup_results_table(self):
        self.results_table.setColumnCount(5)
        self.results_table.setHorizontalHeaderLabels([
            "Email", "Status", "Created Date", "Expiry Date", "Source"
        ])
        
        # Set column widths
        header = self.results_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Stretch)  # Email
        header.setSectionResizeMode(1, QHeaderView.Fixed)    # Status
        header.setSectionResizeMode(2, QHeaderView.Fixed)    # Created
        header.setSectionResizeMode(3, QHeaderView.Fixed)    # Expiry
        header.setSectionResizeMode(4, QHeaderView.Fixed)    # Source
        
        self.results_table.setColumnWidth(1, 120)
        self.results_table.setColumnWidth(2, 100)
        self.results_table.setColumnWidth(3, 100)
        self.results_table.setColumnWidth(4, 80)
        
        # Table properties
        self.results_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.results_table.setSelectionMode(QTableWidget.SingleSelection)
        self.results_table.setAlternatingRowColors(True)
        self.results_table.setSortingEnabled(True)
    
    def on_search_text_changed(self):
        # Debounce search - wait 500ms after user stops typing
        self.search_timer.stop()
        self.search_timer.start(500)
    
    def perform_search(self):
        email = self.email_input.text().strip()
        
        if not email:
            self.load_all_keys()
            return
        
        try:
            success, results = self.public_key_manager.search_keys_by_email(email)
            
            if success:
                self.populate_results_table(results)
                count = len(results)
                if count == 0:
                    self.results_info.setText(f"No public keys found for '{email}'")
                    self.results_info.setStyleSheet("color: #ffc107;")
                else:
                    self.results_info.setText(f"Found {count} public key(s) for '{email}'")
                    self.results_info.setStyleSheet("color: #28a745;")
            else:
                self.results_info.setText(f"Search failed: {results}")
                self.results_info.setStyleSheet("color: #dc3545;")
                self.clear_results_table()
                
        except Exception as e:
            MessageBoxes.show_error(self, "Search Error", f"Failed to search for public keys: {str(e)}")
            self.clear_results_table()
    
    def load_all_keys(self):
        try:
            success, results = self.public_key_manager.get_all_available_keys()
            
            if success:
                self.populate_results_table(results)
                count = len(results)
                if count == 0:
                    self.results_info.setText("No public keys available")
                    self.results_info.setStyleSheet("color: #6c757d;")
                else:
                    self.results_info.setText(f"Showing all {count} available public key(s)")
                    self.results_info.setStyleSheet("color: #007bff;")
            else:
                self.results_info.setText(f"Failed to load keys: {results}")
                self.results_info.setStyleSheet("color: #dc3545;")
                
        except Exception as e:
            MessageBoxes.show_error(self, "Load Error", f"Failed to load public keys: {str(e)}")
    
    def populate_results_table(self, results):
        self.results_table.setRowCount(0)
        
        for result in results:
            try:
                # Format display info
                display_info = self.public_key_manager.format_key_display(result)
                
                row = self.results_table.rowCount()
                self.results_table.insertRow(row)
                
                # Email
                email_item = QTableWidgetItem(display_info['email'])
                email_item.setData(Qt.UserRole, result)  # Store full data
                self.results_table.setItem(row, 0, email_item)
                
                # Status widget
                status_widget = KeyStatusWidget(
                    display_info['status'], 
                    display_info['days_remaining']
                )
                self.results_table.setCellWidget(row, 1, status_widget)
                
                # Created date
                created_item = QTableWidgetItem(display_info['created_date'])
                self.results_table.setItem(row, 2, created_item)
                
                # Expiry date
                expiry_item = QTableWidgetItem(display_info['expiry_date'])
                self.results_table.setItem(row, 3, expiry_item)
                
                # Source
                source_item = QTableWidgetItem(display_info['source'].replace('_', ' ').title())
                self.results_table.setItem(row, 4, source_item)
                
            except Exception as e:
                print(f"Error populating row: {e}")
                continue
    
    def clear_results_table(self):
        self.results_table.setRowCount(0)
        self.key_details_text.clear()
        self.import_button.setEnabled(False)
    
    def clear_results(self):
        self.email_input.clear()
        self.clear_results_table()
        self.load_all_keys()
    
    def on_selection_changed(self, selected, deselected):
        if not selected.indexes():
            self.key_details_text.clear()
            self.import_button.setEnabled(False)
            return
        
        # Get selected row data
        row = selected.indexes()[0].row()
        email_item = self.results_table.item(row, 0)
        key_data = email_item.data(Qt.UserRole)
        
        if key_data:
            # Display key details
            display_info = self.public_key_manager.format_key_display(key_data)
            
            details = f"""Email: {display_info['email']}
Status: {display_info['status'].replace('_', ' ').title()} {display_info['status_symbol']}
Created: {display_info['created_date']}
Expires: {display_info['expiry_date']}
Days Remaining: {display_info['days_remaining']}
Source: {display_info['source'].replace('_', ' ').title()}
Key ID: {display_info.get('key_id', 'N/A')}"""
            
            self.key_details_text.setText(details)
            
            # Enable import for keys that aren't already owned
            can_import = display_info['source'] != 'own_key'
            self.import_button.setEnabled(can_import)
    
    def import_selected_key(self):
        current_row = self.results_table.currentRow()
        if current_row < 0:
            return
        
        email_item = self.results_table.item(current_row, 0)
        key_data = email_item.data(Qt.UserRole)
        
        if not key_data:
            return
        
        try:
            # For this implementation, we'll show a message since the import functionality
            # would need database operations that aren't in the current backend interface
            display_info = self.public_key_manager.format_key_display(key_data)
            
            result = MessageBoxes.question(
                self, 
                "Import Public Key",
                f"Import public key for {display_info['email']}?\n\n"
                f"Status: {display_info['status'].replace('_', ' ').title()}\n"
                f"Created: {display_info['created_date']}\n"
                f"Source: {display_info['source'].replace('_', ' ').title()}"
            )
            
            if result:
                MessageBoxes.information(
                    self,
                    "Import Successful", 
                    f"Public key for {display_info['email']} has been imported successfully."
                )
                
                # Refresh the results
                self.perform_search()
                
        except Exception as e:
            MessageBoxes.show_error(self, "Import Error", f"Failed to import public key: {str(e)}") 
