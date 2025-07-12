import logging
import os
from datetime import datetime
from .database import db

class SecurityLogger:
    def __init__(self):
        self.setup_file_logger()
    
    def setup_file_logger(self):
        os.makedirs('logs', exist_ok=True)
        logging.basicConfig(
            level=logging.INFO,
            format='[%(asctime)s] [%(levelname)s] %(message)s',
            handlers=[
                logging.FileHandler('logs/security.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger('SecurityApp')
    
    def log_activity(self, user_id=None, action=None, status='success', details=None, ip_address='127.0.0.1', email=None):
        """
        Universal logging method for all security activities.
        
        Parameters:
        - user_id: Database user ID (optional)
        - action: The action being logged (required)
        - status: success/failure/warning/info (default: 'success')
        - details: Additional details about the action (optional)
        - ip_address: IP address (default: '127.0.0.1')
        - email: User email address (optional, but recommended for user actions)
        """
        # Log to database
        try:
            query = """
            INSERT INTO activity_logs (user_id, action, status, details, ip_address, email)
            VALUES (?, ?, ?, ?, ?, ?)
            """
            db.execute_query(query, (user_id, action, status, str(details), ip_address, email))
        except Exception as e:
            self.logger.error(f"Failed to log to database: {e}")
        
        # Log to file using the universal format: [Time] Email:<user_email> Action:<action> Status:<status> Details:<detail>
        log_level = logging.INFO if status == 'success' else logging.WARNING if status == 'warning' else logging.ERROR
        user_email = email if email else "None"
        message = f"Email:{user_email} Action:{action} Status:{status} Details:{details}"
        self.logger.log(log_level, message)
    
    def get_logs(self, user_id=None, limit=100):
        """Get activity logs from database"""
        if user_id:
            query = "SELECT * FROM activity_logs WHERE user_id = ? ORDER BY timestamp DESC LIMIT ?"
            return db.execute_query(query, (user_id, limit), fetch=True)
        else:
            query = "SELECT * FROM activity_logs ORDER BY timestamp DESC LIMIT ?"
            return db.execute_query(query, (limit,), fetch=True)

security_logger = SecurityLogger() 