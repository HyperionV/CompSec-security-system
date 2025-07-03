from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional

from .database import db
from .key_manager import key_manager
from .logger import security_logger

class KeyLifecycleService:
    def __init__(self):
        self.warning_days = 7
        self.expiry_days = 90
    
    def run_daily_lifecycle_check(self) -> Tuple[bool, str, Optional[Dict]]:
        """Run complete daily lifecycle management check"""
        try:
            results = {
                'keys_checked': 0,
                'status_updates': 0,
                'warnings_issued': 0,
                'keys_expired': 0,
                'errors': []
            }
            
            # Update all expired keys
            expired_count = self.update_all_expired_keys()
            results['keys_expired'] = expired_count
            
            # Update all expiring keys (warning status)
            expiring_count = self.update_all_expiring_keys()
            results['warnings_issued'] = expiring_count
            
            # Get summary statistics
            summary = self.get_lifecycle_summary()
            results.update(summary)
            
            security_logger.log_activity(
                action='daily_lifecycle_check',
                status='success',
                details=f'Processed lifecycle for {results["keys_checked"]} keys'
            )
            
            return True, "Daily lifecycle check completed successfully", results
            
        except Exception as e:
            security_logger.log_activity(
                action='daily_lifecycle_check',
                status='failure',
                details=f'Lifecycle check failed: {str(e)}'
            )
            return False, f"Daily lifecycle check failed: {str(e)}", None
    
    def update_all_expired_keys(self) -> int:
        """Update status of all keys that have expired"""
        try:
            return db.update_expired_keys()
        except Exception as e:
            security_logger.log_activity(
                action='update_expired_keys',
                status='failure',
                details=f'Failed to update expired keys: {str(e)}'
            )
            return 0
    
    def update_all_expiring_keys(self) -> int:
        """Update status of all keys approaching expiration"""
        try:
            return db.update_expiring_keys(self.warning_days)
        except Exception as e:
            security_logger.log_activity(
                action='update_expiring_keys',
                status='failure',
                details=f'Failed to update expiring keys: {str(e)}'
            )
            return 0
    
    def get_expiring_keys_report(self) -> Tuple[bool, str, Optional[List]]:
        """Get detailed report of keys requiring attention"""
        try:
            expiring_keys = db.get_expiring_keys(self.warning_days)
            expired_keys = db.get_expired_keys()
            
            report = []
            
            # Add expiring keys to report
            for key in expiring_keys:
                expires_at = key['expires_at']
                if isinstance(expires_at, str):
                    expires_at = datetime.fromisoformat(expires_at)
                
                days_remaining = (expires_at - datetime.now()).days
                
                report.append({
                    'key_id': key['id'],
                    'user_email': key['email'],
                    'user_name': key['name'],
                    'created_at': key['created_at'].isoformat() if hasattr(key['created_at'], 'isoformat') else str(key['created_at']),
                    'expires_at': expires_at.isoformat() if hasattr(expires_at, 'isoformat') else str(expires_at),
                    'status': key['status'],
                    'days_remaining': days_remaining,
                    'urgency': 'expiring'
                })
            
            # Add expired keys to report
            for key in expired_keys:
                expires_at = key['expires_at']
                if isinstance(expires_at, str):
                    expires_at = datetime.fromisoformat(expires_at)
                
                days_overdue = (datetime.now() - expires_at).days
                
                report.append({
                    'key_id': key['id'],
                    'user_email': key['email'],
                    'user_name': key['name'],
                    'created_at': key['created_at'].isoformat() if hasattr(key['created_at'], 'isoformat') else str(key['created_at']),
                    'expires_at': expires_at.isoformat() if hasattr(expires_at, 'isoformat') else str(expires_at),
                    'status': 'expired',
                    'days_overdue': days_overdue,
                    'urgency': 'expired'
                })
            
            return True, f"Found {len(report)} keys requiring attention", report
            
        except Exception as e:
            security_logger.log_activity(
                action='expiring_keys_report',
                status='failure',
                details=f'Failed to generate report: {str(e)}'
            )
            return False, f"Failed to generate expiring keys report: {str(e)}", None
    
    def get_lifecycle_summary(self) -> Dict:
        """Get summary statistics for all key lifecycle states"""
        try:
            # Get counts for each status
            valid_count = db.execute_query(
                "SELECT COUNT(*) as count FROM keys WHERE status = 'valid'", 
                fetch=True
            )[0]['count']
            
            expiring_count = db.execute_query(
                "SELECT COUNT(*) as count FROM keys WHERE status = 'expiring'", 
                fetch=True
            )[0]['count']
            
            expired_count = db.execute_query(
                "SELECT COUNT(*) as count FROM keys WHERE status = 'expired'", 
                fetch=True
            )[0]['count']
            
            total_count = valid_count + expiring_count + expired_count
            
            return {
                'total_keys': total_count,
                'valid_keys': valid_count,
                'expiring_keys': expiring_count,
                'expired_keys': expired_count,
                'health_percentage': round((valid_count / total_count * 100), 2) if total_count > 0 else 0
            }
            
        except Exception as e:
            security_logger.log_activity(
                action='lifecycle_summary',
                status='failure',
                details=f'Failed to get summary: {str(e)}'
            )
            return {
                'total_keys': 0,
                'valid_keys': 0,
                'expiring_keys': 0,
                'expired_keys': 0,
                'health_percentage': 0
            }
    
    def check_user_key_status(self, user_id: int) -> Tuple[bool, str, Optional[Dict]]:
        """Check and update key status for specific user"""
        try:
            success, message, key_data = key_manager.check_key_status(user_id)
            
            if success:
                security_logger.log_activity(
                    user_id=user_id,
                    action='key_status_check',
                    status='success',
                    details=f'Key status: {key_data["status"]}'
                )
            
            return success, message, key_data
            
        except Exception as e:
            security_logger.log_activity(
                user_id=user_id,
                action='key_status_check',
                status='failure',
                details=f'Status check failed: {str(e)}'
            )
            return False, f"Key status check failed: {str(e)}", None
    
    def renew_user_keys(self, user_id: int, passphrase: str) -> Tuple[bool, str, Optional[Dict]]:
        """Renew keys for specific user"""
        try:
            success, message, key_data = key_manager.renew_user_keys(user_id, passphrase)
            
            if success:
                security_logger.log_activity(
                    user_id=user_id,
                    action='key_renewal',
                    status='success',
                    details='Keys renewed successfully'
                )
            
            return success, message, key_data
            
        except Exception as e:
            security_logger.log_activity(
                user_id=user_id,
                action='key_renewal',
                status='failure',
                details=f'Key renewal failed: {str(e)}'
            )
            return False, f"Key renewal failed: {str(e)}", None
    
    def get_users_needing_key_renewal(self) -> Tuple[bool, str, Optional[List]]:
        """Get list of users who need key renewal (expired or expiring keys)"""
        try:
            query = """
            SELECT DISTINCT u.id, u.email, u.name, k.status, k.expires_at
            FROM users u
            JOIN keys k ON u.id = k.user_id
            WHERE k.status IN ('expiring', 'expired')
            ORDER BY k.expires_at ASC
            """
            
            results = db.execute_query(query, fetch=True)
            
            users_list = []
            for result in results:
                expires_at = result['expires_at']
                if isinstance(expires_at, str):
                    expires_at = datetime.fromisoformat(expires_at)
                
                if result['status'] == 'expired':
                    days_info = (datetime.now() - expires_at).days
                    urgency = f"{days_info} days overdue"
                else:
                    days_info = (expires_at - datetime.now()).days
                    urgency = f"{days_info} days remaining"
                
                users_list.append({
                    'user_id': result['id'],
                    'email': result['email'],
                    'name': result['name'],
                    'key_status': result['status'],
                    'expires_at': expires_at.isoformat(),
                    'urgency': urgency
                })
            
            return True, f"Found {len(users_list)} users needing key renewal", users_list
            
        except Exception as e:
            security_logger.log_activity(
                action='users_needing_renewal',
                status='failure',
                details=f'Failed to get renewal list: {str(e)}'
            )
            return False, f"Failed to get users needing renewal: {str(e)}", None
    
    def cleanup_expired_otps(self) -> int:
        """Clean up expired OTP codes as part of lifecycle management"""
        try:
            return db.cleanup_expired_otps()
        except Exception as e:
            security_logger.log_activity(
                action='otp_cleanup',
                status='failure',
                details=f'OTP cleanup failed: {str(e)}'
            )
            return 0
    
    def generate_lifecycle_report(self) -> Tuple[bool, str, Optional[Dict]]:
        """Generate comprehensive lifecycle management report"""
        try:
            report = {}
            
            # Get summary statistics
            report['summary'] = self.get_lifecycle_summary()
            
            # Get expiring keys report
            success, message, expiring_report = self.get_expiring_keys_report()
            if success:
                report['keys_needing_attention'] = expiring_report
            else:
                report['keys_needing_attention'] = []
            
            # Get users needing renewal
            success, message, users_report = self.get_users_needing_key_renewal()
            if success:
                report['users_needing_renewal'] = users_report
            else:
                report['users_needing_renewal'] = []
            
            # Add timestamp
            report['generated_at'] = datetime.now().isoformat()
            
            security_logger.log_activity(
                action='lifecycle_report',
                status='success',
                details='Comprehensive lifecycle report generated'
            )
            
            return True, "Lifecycle report generated successfully", report
            
        except Exception as e:
            security_logger.log_activity(
                action='lifecycle_report',
                status='failure',
                details=f'Report generation failed: {str(e)}'
            )
            return False, f"Failed to generate lifecycle report: {str(e)}", None

# Create global instance
lifecycle_service = KeyLifecycleService()
