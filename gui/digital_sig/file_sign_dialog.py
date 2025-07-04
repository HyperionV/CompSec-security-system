import os
from PyQt5.QtWidgets import (QVBoxLayout, QHBoxLayout, QLabel, QPushButton, 
                             QLineEdit, QGroupBox, QTextEdit, QProgressBar,
                             QFileDialog, QFrame)
from PyQt5.QtCore import QThread, Qt
from PyQt5.QtGui import QFont
from gui.base.base_dialog import BaseDialog
from gui.utils.message_boxes import MessageBoxes
from .signing_worker import SigningWorker

class FileSignDialog(BaseDialog):
    def __init__(self, session_manager, parent=None):
        super().__init__("Sign File", parent)
        self.session_manager = session_manager
        self.selected_file = None
        self.worker_thread = None
        self.worker = None
        self.setupUI()

    def setupUI(self):
        layout = QVBoxLayout()

        # File selection section
        file_group = QGroupBox("File Selection")
        file_layout = QVBoxLayout()

        self.file_label = QLabel("No file selected")
        self.file_label.setStyleSheet("color: gray; padding: 10px; border: 1px dashed #ccc;")
        self.file_label.setMinimumHeight(60)
        self.file_label.setAlignment(Qt.AlignCenter)

        file_buttons_layout = QHBoxLayout()
        self.browse_button = QPushButton("Browse File")
        self.browse_button.clicked.connect(self.browse_file)
        file_buttons_layout.addWidget(self.browse_button)
        file_buttons_layout.addStretch()

        file_layout.addWidget(self.file_label)
        file_layout.addLayout(file_buttons_layout)
        file_group.setLayout(file_layout)

        # Passphrase section
        passphrase_group = QGroupBox("Authentication")
        passphrase_layout = QVBoxLayout()

        passphrase_label = QLabel("Enter your passphrase to access private key:")
        self.passphrase_input = QLineEdit()
        self.passphrase_input.setEchoMode(QLineEdit.Password)
        self.passphrase_input.setPlaceholderText("Enter passphrase...")
        self.passphrase_input.textChanged.connect(self.update_sign_button_state)

        show_passphrase_layout = QHBoxLayout()
        self.show_passphrase_button = QPushButton("Show")
        self.show_passphrase_button.setMaximumWidth(60)
        self.show_passphrase_button.clicked.connect(self.toggle_passphrase_visibility)
        show_passphrase_layout.addWidget(self.passphrase_input)
        show_passphrase_layout.addWidget(self.show_passphrase_button)

        passphrase_layout.addWidget(passphrase_label)
        passphrase_layout.addLayout(show_passphrase_layout)
        passphrase_group.setLayout(passphrase_layout)

        # Progress section
        progress_group = QGroupBox("Signing Progress")
        progress_layout = QVBoxLayout()

        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)

        self.status_label = QLabel("Ready to sign file")
        self.status_label.setAlignment(Qt.AlignCenter)

        progress_layout.addWidget(self.progress_bar)
        progress_layout.addWidget(self.status_label)
        progress_group.setLayout(progress_layout)

        # Results section
        results_group = QGroupBox("Signing Results")
        results_layout = QVBoxLayout()

        self.results_text = QTextEdit()
        self.results_text.setMaximumHeight(100)
        self.results_text.setReadOnly(True)
        self.results_text.setPlaceholderText("Signing results will appear here...")

        results_layout.addWidget(self.results_text)
        results_group.setLayout(results_layout)

        # Action buttons
        buttons_layout = QHBoxLayout()
        self.sign_button = QPushButton("Sign File")
        self.sign_button.clicked.connect(self.sign_file)
        self.sign_button.setEnabled(False)

        self.close_button = QPushButton("Close")
        self.close_button.clicked.connect(self.close)

        buttons_layout.addStretch()
        buttons_layout.addWidget(self.sign_button)
        buttons_layout.addWidget(self.close_button)

        layout.addWidget(file_group)
        layout.addWidget(passphrase_group)
        layout.addWidget(progress_group)
        layout.addWidget(results_group)
        layout.addLayout(buttons_layout)

        self.setLayout(layout)
        self.resize(500, 600)

    def browse_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select File to Sign",
            "",
            "All Files (*.*)"
        )
        
        if file_path:
            self.selected_file = file_path
            filename = os.path.basename(file_path)
            file_size = os.path.getsize(file_path)
            size_mb = file_size / (1024 * 1024)
            
            self.file_label.setText(f"File: {filename}\nSize: {size_mb:.2f} MB")
            self.file_label.setStyleSheet("color: black; padding: 10px; border: 1px solid #ccc;")
            self.update_sign_button_state()

    def toggle_passphrase_visibility(self):
        if self.passphrase_input.echoMode() == QLineEdit.Password:
            self.passphrase_input.setEchoMode(QLineEdit.Normal)
            self.show_passphrase_button.setText("Hide")
        else:
            self.passphrase_input.setEchoMode(QLineEdit.Password)
            self.show_passphrase_button.setText("Show")

    def update_sign_button_state(self):
        self.sign_button.setEnabled(
            self.selected_file is not None and 
            len(self.passphrase_input.text().strip()) > 0
        )

    def sign_file(self):
        if not self.selected_file or not self.passphrase_input.text().strip():
            MessageBoxes.warning(self, "Missing Information", "Please select a file and enter your passphrase.")
            return

        self.sign_button.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)
        self.status_label.setText("Starting signing process...")
        self.results_text.clear()

        # Setup worker thread
        self.worker_thread = QThread()
        self.worker = SigningWorker(
            self.session_manager.current_user.email,
            self.session_manager.key_manager,
            self.session_manager.database,
            self.session_manager.logger
        )

        self.worker.set_signing_data(self.selected_file, self.passphrase_input.text())
        self.worker.moveToThread(self.worker_thread)

        # Connect signals
        self.worker_thread.started.connect(self.worker.run)
        self.worker.progress.connect(self.update_progress)
        self.worker.signed.connect(self.on_signing_complete)
        self.worker.error.connect(self.on_signing_error)
        self.worker.finished.connect(self.cleanup_worker)

        self.worker_thread.start()

    def update_progress(self, message):
        self.status_label.setText(message)

    def on_signing_complete(self, original_file, signature_file):
        self.progress_bar.setVisible(False)
        self.status_label.setText("File signed successfully!")
        
        filename = os.path.basename(original_file)
        sig_filename = os.path.basename(signature_file)
        
        result_text = f"✓ File '{filename}' signed successfully!\n"
        result_text += f"Signature saved as: {sig_filename}\n"
        result_text += f"Location: {signature_file}"
        
        self.results_text.setPlainText(result_text)
        self.results_text.setStyleSheet("color: green;")
        
        MessageBoxes.info(self, "Success", f"File signed successfully!\nSignature saved as: {sig_filename}")

    def on_signing_error(self, error_message):
        self.progress_bar.setVisible(False)
        self.status_label.setText("Signing failed")
        
        self.results_text.setPlainText(f"✗ Signing failed: {error_message}")
        self.results_text.setStyleSheet("color: red;")
        
        MessageBoxes.show_error(self, "Signing Failed", error_message)

    def cleanup_worker(self):
        if self.worker_thread:
            self.worker_thread.quit()
            self.worker_thread.wait()
            self.worker_thread = None
            self.worker = None
        
        self.sign_button.setEnabled(True)

    def closeEvent(self, event):
        if self.worker_thread and self.worker_thread.isRunning():
            self.worker_thread.quit()
            self.worker_thread.wait()
        event.accept() 
