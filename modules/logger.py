import logging
import os
from datetime import datetime
from logging.handlers import RotatingFileHandler
from config.config import FILE_CONFIG

class SecurityLogger:
    _instance = None
    _logger = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._setup_logger()
        return cls._instance
    
    @classmethod
    def _setup_logger(cls):
        cls._logger = logging.getLogger('SecurityApp')
        cls._logger.setLevel(logging.DEBUG)
        
        if not cls._logger.handlers:
            log_dir = FILE_CONFIG['log_directory']
            os.makedirs(log_dir, exist_ok=True)
            log_file = os.path.join(log_dir, 'security.log')
            
            file_handler = RotatingFileHandler(
                log_file, 
                maxBytes=10*1024*1024,  # 10MB
                backupCount=5
            )
            
            console_handler = logging.StreamHandler()
            
            formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] [%(user)s] [%(action)s] [%(status)s] [%(details)s]')
            file_handler.setFormatter(formatter)
            console_handler.setFormatter(formatter)
            
            cls._logger.addHandler(file_handler)
            cls._logger.addHandler(console_handler)
    
    def _log_event(self, level, user, action, status, details):
        extra = {
            'user': user or 'SYSTEM',
            'action': action,
            'status': status,
            'details': details
        }
        
        if level == 'DEBUG':
            self._logger.debug('', extra=extra)
        elif level == 'INFO':
            self._logger.info('', extra=extra)
        elif level == 'WARNING':
            self._logger.warning('', extra=extra)
        elif level == 'ERROR':
            self._logger.error('', extra=extra)
        elif level == 'CRITICAL':
            self._logger.critical('', extra=extra)
    
    # Authentication Events
    def log_auth_success(self, user, details=""):
        self._log_event('INFO', user, 'LOGIN', 'SUCCESS', details)
    
    def log_auth_failure(self, user, details=""):
        self._log_event('WARNING', user, 'LOGIN', 'FAILED', details)
    
    def log_registration(self, user, details=""):
        self._log_event('INFO', user, 'REGISTRATION', 'SUCCESS', details)
    
    def log_logout(self, user, details=""):
        self._log_event('INFO', user, 'LOGOUT', 'SUCCESS', details)
    
    def log_password_change(self, user, details=""):
        self._log_event('INFO', user, 'PASSWORD_CHANGE', 'SUCCESS', details)
    
    # Account Security Events
    def log_account_locked(self, user, details=""):
        self._log_event('WARNING', user, 'ACCOUNT_LOCK', 'LOCKED', details)
    
    def log_failed_attempts(self, user, attempt_count, details=""):
        self._log_event('WARNING', user, 'FAILED_ATTEMPTS', f'COUNT_{attempt_count}', details)
    
    # Cryptographic Events
    def log_key_generation(self, user, key_type, details=""):
        self._log_event('INFO', user, f'KEY_GENERATION_{key_type}', 'SUCCESS', details)
    
    def log_encryption(self, user, operation, details=""):
        self._log_event('INFO', user, f'ENCRYPTION_{operation}', 'SUCCESS', details)
    
    def log_decryption(self, user, operation, details=""):
        self._log_event('INFO', user, f'DECRYPTION_{operation}', 'SUCCESS', details)
    
    def log_signature_creation(self, user, details=""):
        self._log_event('INFO', user, 'SIGNATURE_CREATE', 'SUCCESS', details)
    
    def log_signature_verification(self, user, result, details=""):
        status = 'SUCCESS' if result else 'FAILED'
        self._log_event('INFO', user, 'SIGNATURE_VERIFY', status, details)
    
    # Database Events
    def log_database_connection(self, status, details=""):
        level = 'INFO' if status == 'SUCCESS' else 'ERROR'
        self._log_event(level, 'SYSTEM', 'DB_CONNECTION', status, details)
    
    def log_user_creation(self, admin_user, target_user, details=""):
        self._log_event('INFO', admin_user, 'USER_CREATE', 'SUCCESS', f'Created user: {target_user}. {details}')
    
    # Admin Events
    def log_admin_action(self, admin_user, action, target, details=""):
        self._log_event('WARNING', admin_user, f'ADMIN_{action}', 'EXECUTED', f'Target: {target}. {details}')
    
    def log_config_change(self, user, setting, details=""):
        self._log_event('WARNING', user, 'CONFIG_CHANGE', 'MODIFIED', f'Setting: {setting}. {details}')
    
    # Security Events
    def log_security_violation(self, user, violation_type, details=""):
        self._log_event('CRITICAL', user, f'SECURITY_VIOLATION_{violation_type}', 'DETECTED', details)
    
    def log_suspicious_activity(self, user, activity, details=""):
        self._log_event('WARNING', user, f'SUSPICIOUS_{activity}', 'DETECTED', details)
    
    # System Events
    def log_system_startup(self, details=""):
        self._log_event('INFO', 'SYSTEM', 'STARTUP', 'SUCCESS', details)
    
    def log_system_shutdown(self, details=""):
        self._log_event('INFO', 'SYSTEM', 'SHUTDOWN', 'SUCCESS', details)
    
    def log_error(self, user, error_type, details=""):
        self._log_event('ERROR', user or 'SYSTEM', f'ERROR_{error_type}', 'OCCURRED', details)

# Global instance
security_logger = SecurityLogger()

# Convenience functions for easy import
def log_auth_success(user, details=""):
    security_logger.log_auth_success(user, details)

def log_auth_failure(user, details=""):
    security_logger.log_auth_failure(user, details)

def log_registration(user, details=""):
    security_logger.log_registration(user, details)

def log_crypto_operation(user, operation, details=""):
    if 'encrypt' in operation.lower():
        security_logger.log_encryption(user, operation, details)
    elif 'decrypt' in operation.lower():
        security_logger.log_decryption(user, operation, details)
    elif 'sign' in operation.lower():
        security_logger.log_signature_creation(user, details)

def log_admin_action(admin_user, action, target="", details=""):
    security_logger.log_admin_action(admin_user, action, target, details)

def log_error(user, error_type, details=""):
    security_logger.log_error(user, error_type, details)

def log_database_event(status, details=""):
    security_logger.log_database_connection(status, details) 