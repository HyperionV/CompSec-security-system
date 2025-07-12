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
        # Log to database
        try:
            query = """
            INSERT INTO activity_logs (user_id, action, status, details, ip_address, email)
            VALUES (?, ?, ?, ?, ?, ?)
            """
            db.execute_query(query, (user_id, action, status, str(details), ip_address, email))
        except Exception as e:
            self.logger.error(f"Failed to log to database: {e}")
        
        # Log to file using the new universal format: [Time] Email:<user_email> Action:<action> Status:<status> Details:<detail>
        log_level = logging.INFO if status == 'success' else logging.WARNING if status == 'warning' else logging.ERROR
        user_email = email if email else "None"
        message = f"Email:{user_email} Action:{action} Status:{status} Details:{details}"
        self.logger.log(log_level, message)
    
    def log_action(self, user_email, action, status, details=None):
        """Backward compatibility method for modules using log_action"""
        self.log_activity(email=user_email, action=action, status=status, details=details)
    
    def log_auth_attempt(self, email, success=True, details=None):
        status = 'success' if success else 'failure'
        action = 'login_attempt'
        self.log_activity(action=action, status=status, details=details, email=email)
    
    def log_registration(self, email, success=True, details=None):
        status = 'success' if success else 'failure'
        action = 'user_registration'
        self.log_activity(action=action, status=status, details=details, email=email)
    
    def log_key_operation(self, user_id, operation, success=True, details=None, email=None):
        status = 'success' if success else 'failure'
        action = f'key_{operation}'
        self.log_activity(user_id=user_id, action=action, status=status, details=details, email=email)
    
    def log_file_operation(self, user_id, operation, filename=None, success=True, details=None, email=None):
        status = 'success' if success else 'failure'
        action = f'file_{operation}'
        file_info = f"File: {filename}" if filename else ""
        full_details = f"{file_info} {details or ''}".strip()
        self.log_activity(user_id=user_id, action=action, status=status, details=full_details, email=email)
    
    def log_admin_action(self, admin_id, action, target_user=None, success=True, details=None, email=None):
        status = 'success' if success else 'failure'
        target_info = f"Target: {target_user}" if target_user else ""
        full_details = f"{target_info} {details or ''}".strip()
        self.log_activity(user_id=admin_id, action=f'admin_{action}', status=status, details=full_details, email=email)
    
    def log_action(self, user_identifier, action, status='success', details=None):
        """Compatibility wrapper for legacy code expecting log_action.
        Records the event via log_activity while embedding the user identifier (email or ID)
        into the details field. This prevents AttributeError without changing other modules.
        """
        # Normalize status to lowercase for consistency
        normalized_status = status.lower()
        # Prepend actor information to details for traceability
        wrapped_details = f"Actor:{user_identifier} | {details or ''}"
        # Delegate to core log_activity
        self.log_activity(user_id=None, action=action, status=normalized_status, details=wrapped_details)
    
    def get_logs(self, user_id=None, limit=100):
        if user_id:
            query = "SELECT * FROM activity_logs WHERE user_id = ? ORDER BY timestamp DESC LIMIT ?"
            return db.execute_query(query, (user_id, limit), fetch=True)
        else:
            query = "SELECT * FROM activity_logs ORDER BY timestamp DESC LIMIT ?"
            return db.execute_query(query, (limit,), fetch=True)

security_logger = SecurityLogger() 