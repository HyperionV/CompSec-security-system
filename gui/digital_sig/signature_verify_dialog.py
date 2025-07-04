import os
from PyQt5.QtWidgets import (QVBoxLayout, QHBoxLayout, QLabel, QPushButton, 
                             QGroupBox, QTextEdit, QProgressBar, QFileDialog,
                             QFrame, QCheckBox, QScrollArea, QWidget, QTableWidget,
                             QTableWidgetItem, QHeaderView)
from PyQt5.QtCore import QThread, Qt
from PyQt5.QtGui import QFont, QPixmap, QPalette
from gui.base.base_dialog import BaseDialog
from gui.utils.message_boxes import MessageBoxes
from .verification_worker import VerificationWorker

class SignatureVerifyDialog(BaseDialog):
    def __init__(self, session_manager, parent=None):
        super().__init__("Verify Signature", parent)
        self.session_manager = session_manager
        self.selected_file = None
        self.selected_signature = None
        self.worker_thread = None
        self.worker = None
        self.setupUI()

    def setupUI(self):
        layout = QVBoxLayout()

        # File selection section
        file_group = QGroupBox("File Selection")
        file_layout = QVBoxLayout()

        # Original file selection
        original_file_layout = QHBoxLayout()
        original_file_label = QLabel("Original File:")
        self.file_label = QLabel("No file selected")
        self.file_label.setStyleSheet("color: gray; padding: 5px; border: 1px dashed #ccc;")
        self.browse_file_button = QPushButton("Browse File")
        self.browse_file_button.clicked.connect(self.browse_file)

        original_file_layout.addWidget(original_file_label)
        original_file_layout.addWidget(self.file_label, 1)
        original_file_layout.addWidget(self.browse_file_button)

        # Signature file selection
        signature_file_layout = QHBoxLayout()
        signature_file_label = QLabel("Signature File:")
        self.signature_label = QLabel("Auto-detect or select manually")
        self.signature_label.setStyleSheet("color: gray; padding: 5px; border: 1px dashed #ccc;")
        self.browse_signature_button = QPushButton("Browse Signature")
        self.browse_signature_button.clicked.connect(self.browse_signature)

        signature_file_layout.addWidget(signature_file_label)
        signature_file_layout.addWidget(self.signature_label, 1)
        signature_file_layout.addWidget(self.browse_signature_button)

        file_layout.addLayout(original_file_layout)
        file_layout.addLayout(signature_file_layout)
        file_group.setLayout(file_layout)

        # Progress section
        progress_group = QGroupBox("Verification Progress")
        progress_layout = QVBoxLayout()

        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)

        self.status_label = QLabel("Ready to verify signature")
        self.status_label.setAlignment(Qt.AlignCenter)

        progress_layout.addWidget(self.progress_bar)
        progress_layout.addWidget(self.status_label)
        progress_group.setLayout(progress_layout)

        # Results section
        results_group = QGroupBox("Verification Results")
        results_layout = QVBoxLayout()

        # Status indicator
        status_layout = QHBoxLayout()
        self.status_icon = QLabel("●")
        self.status_icon.setStyleSheet("color: gray; font-size: 24px;")
        self.result_label = QLabel("No verification performed")
        self.result_label.setStyleSheet("font-weight: bold; font-size: 14px;")
        
        status_layout.addWidget(self.status_icon)
        status_layout.addWidget(self.result_label)
        status_layout.addStretch()

        # Details section
        self.details_widget = QWidget()
        details_layout = QVBoxLayout()

        self.details_table = QTableWidget()
        self.details_table.setColumnCount(2)
        self.details_table.setHorizontalHeaderLabels(["Property", "Value"])
        self.details_table.horizontalHeader().setStretchLastSection(True)
        self.details_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.details_table.setMaximumHeight(200)
        self.details_table.setVisible(False)

        self.show_details_button = QPushButton("Show Details")
        self.show_details_button.clicked.connect(self.toggle_details)
        self.show_details_button.setVisible(False)

        details_layout.addWidget(self.show_details_button)
        details_layout.addWidget(self.details_table)
        self.details_widget.setLayout(details_layout)

        results_layout.addLayout(status_layout)
        results_layout.addWidget(self.details_widget)
        results_group.setLayout(results_layout)

        # Action buttons
        buttons_layout = QHBoxLayout()
        self.verify_button = QPushButton("Verify Signature")
        self.verify_button.clicked.connect(self.verify_signature)
        self.verify_button.setEnabled(False)

        self.close_button = QPushButton("Close")
        self.close_button.clicked.connect(self.close)

        buttons_layout.addStretch()
        buttons_layout.addWidget(self.verify_button)
        buttons_layout.addWidget(self.close_button)

        layout.addWidget(file_group)
        layout.addWidget(progress_group)
        layout.addWidget(results_group)
        layout.addLayout(buttons_layout)

        self.setLayout(layout)
        self.resize(600, 500)

    def browse_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select File to Verify",
            "",
            "All Files (*.*)"
        )
        
        if file_path:
            self.selected_file = file_path
            filename = os.path.basename(file_path)
            
            self.file_label.setText(filename)
            self.file_label.setStyleSheet("color: black; padding: 5px; border: 1px solid #ccc;")
            
            # Auto-detect signature file
            potential_sig = file_path + ".sig"
            if os.path.exists(potential_sig):
                self.selected_signature = potential_sig
                sig_filename = os.path.basename(potential_sig)
                self.signature_label.setText(f"Auto-detected: {sig_filename}")
                self.signature_label.setStyleSheet("color: green; padding: 5px; border: 1px solid #ccc;")
            else:
                self.signature_label.setText("No signature file found - select manually")
                self.signature_label.setStyleSheet("color: orange; padding: 5px; border: 1px dashed #ccc;")
            
            self.update_verify_button_state()

    def browse_signature(self):
        if not self.selected_file:
            MessageBoxes.warning(self, "No File Selected", "Please select the original file first.")
            return

        file_dir = os.path.dirname(self.selected_file)
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Signature File",
            file_dir,
            "Signature Files (*.sig);;All Files (*.*)"
        )
        
        if file_path:
            self.selected_signature = file_path
            filename = os.path.basename(file_path)
            self.signature_label.setText(filename)
            self.signature_label.setStyleSheet("color: black; padding: 5px; border: 1px solid #ccc;")
            self.update_verify_button_state()

    def update_verify_button_state(self):
        self.verify_button.setEnabled(
            self.selected_file is not None and 
            self.selected_signature is not None
        )

    def verify_signature(self):
        if not self.selected_file:
            MessageBoxes.warning(self, "Missing Information", "Please select a file to verify.")
            return

        self.verify_button.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)
        self.status_label.setText("Starting verification...")
        self.reset_results()

        # Setup worker thread
        self.worker_thread = QThread()
        self.worker = VerificationWorker(
            self.session_manager.current_user.email,
            self.session_manager.database,
            self.session_manager.logger
        )

        self.worker.set_verification_data(self.selected_file, self.selected_signature)
        self.worker.moveToThread(self.worker_thread)

        # Connect signals
        self.worker_thread.started.connect(self.worker.run)
        self.worker.progress.connect(self.update_progress)
        self.worker.verified.connect(self.on_verification_complete)
        self.worker.error.connect(self.on_verification_error)
        self.worker.finished.connect(self.cleanup_worker)

        self.worker_thread.start()

    def update_progress(self, message):
        self.status_label.setText(message)

    def on_verification_complete(self, success, message, metadata):
        self.progress_bar.setVisible(False)
        
        if success:
            self.status_icon.setStyleSheet("color: green; font-size: 24px;")
            self.status_icon.setText("✓")
            self.result_label.setText("SIGNATURE VALID")
            self.result_label.setStyleSheet("color: green; font-weight: bold; font-size: 14px;")
            self.status_label.setText("Signature verification successful!")
            
            if metadata:
                self.populate_details_table(metadata)
                self.show_details_button.setVisible(True)
        else:
            self.status_icon.setStyleSheet("color: red; font-size: 24px;")
            self.status_icon.setText("✗")
            self.result_label.setText("SIGNATURE INVALID")
            self.result_label.setStyleSheet("color: red; font-weight: bold; font-size: 14px;")
            self.status_label.setText("Signature verification failed!")

    def on_verification_error(self, error_message):
        self.progress_bar.setVisible(False)
        self.status_icon.setStyleSheet("color: orange; font-size: 24px;")
        self.status_icon.setText("⚠")
        self.result_label.setText("VERIFICATION ERROR")
        self.result_label.setStyleSheet("color: orange; font-weight: bold; font-size: 14px;")
        self.status_label.setText(f"Error: {error_message}")
        
        MessageBoxes.show_error(self, "Verification Error", error_message)

    def populate_details_table(self, metadata):
        self.details_table.setRowCount(len(metadata))
        
        row = 0
        for key, value in metadata.items():
            # Format key for display
            display_key = key.replace('_', ' ').title()
            
            # Format value for display
            if key == 'timestamp':
                try:
                    from datetime import datetime
                    dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
                    display_value = dt.strftime('%Y-%m-%d %H:%M:%S UTC')
                except:
                    display_value = str(value)
            elif key == 'file_hash':
                display_value = f"{value[:16]}..." if len(value) > 16 else value
            else:
                display_value = str(value)
            
            self.details_table.setItem(row, 0, QTableWidgetItem(display_key))
            self.details_table.setItem(row, 1, QTableWidgetItem(display_value))
            row += 1

    def toggle_details(self):
        if self.details_table.isVisible():
            self.details_table.setVisible(False)
            self.show_details_button.setText("Show Details")
        else:
            self.details_table.setVisible(True)
            self.show_details_button.setText("Hide Details")

    def reset_results(self):
        self.status_icon.setStyleSheet("color: gray; font-size: 24px;")
        self.status_icon.setText("●")
        self.result_label.setText("Verifying...")
        self.result_label.setStyleSheet("font-weight: bold; font-size: 14px;")
        self.details_table.setVisible(False)
        self.show_details_button.setVisible(False)
        self.show_details_button.setText("Show Details")

    def cleanup_worker(self):
        if self.worker_thread:
            self.worker_thread.quit()
            self.worker_thread.wait()
            self.worker_thread = None
            self.worker = None
        
        self.verify_button.setEnabled(True)

    def closeEvent(self, event):
        if self.worker_thread and self.worker_thread.isRunning():
            self.worker_thread.quit()
            self.worker_thread.wait()
        event.accept() 
