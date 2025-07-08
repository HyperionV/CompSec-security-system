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
    
    def log_activity(self, user_id=None, action=None, status='success', details=None, ip_address='127.0.0.1'):
        # Log to database
        try:
            query = """
            INSERT INTO activity_logs (user_id, action, status, details, ip_address)
            VALUES (?, ?, ?, ?, ?)
            """
            db.execute_query(query, (user_id, action, status, str(details), ip_address)) # Explicitly cast details to str
        except Exception as e:
            self.logger.error(f"Failed to log to database: {e}")
        
        # Log to file
        log_level = logging.INFO if status == 'success' else logging.WARNING if status == 'warning' else logging.ERROR
        message = f"User:{user_id} Action:{action} Status:{status} Details:{details}"
        self.logger.log(log_level, message)
    
    def log_auth_attempt(self, email, success=True, details=None):
        status = 'success' if success else 'failure'
        action = 'login_attempt'
        self.log_activity(action=action, status=status, details=f"Email: {email}, {details or ''}")
    
    def log_registration(self, email, success=True, details=None):
        status = 'success' if success else 'failure'
        action = 'user_registration'
        self.log_activity(action=action, status=status, details=f"Email: {email}, {details or ''}")
    
    def log_key_operation(self, user_id, operation, success=True, details=None):
        status = 'success' if success else 'failure'
        action = f'key_{operation}'
        self.log_activity(user_id=user_id, action=action, status=status, details=details)
    
    def log_file_operation(self, user_id, operation, filename=None, success=True, details=None):
        status = 'success' if success else 'failure'
        action = f'file_{operation}'
        file_info = f"File: {filename}" if filename else ""
        full_details = f"{file_info} {details or ''}".strip()
        self.log_activity(user_id=user_id, action=action, status=status, details=full_details)
    
    def log_admin_action(self, admin_id, action, target_user=None, success=True, details=None):
        status = 'success' if success else 'failure'
        target_info = f"Target: {target_user}" if target_user else ""
        full_details = f"{target_info} {details or ''}".strip()
        self.log_activity(user_id=admin_id, action=f'admin_{action}', status=status, details=full_details)
    
    def get_logs(self, user_id=None, limit=100):
        if user_id:
            query = "SELECT * FROM activity_logs WHERE user_id = ? ORDER BY timestamp DESC LIMIT ?"
            return db.execute_query(query, (user_id, limit), fetch=True)
        else:
            query = "SELECT * FROM activity_logs ORDER BY timestamp DESC LIMIT ?"
            return db.execute_query(query, (limit,), fetch=True)

security_logger = SecurityLogger() 