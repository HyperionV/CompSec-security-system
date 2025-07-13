# Security Audit Logging

This document details the Security Audit Logging feature of the Security Application, covering data flow, usage, and underlying security principles.

## 1. Data Flow (Class and Function Level)

### 1.1. Log Generation and Storage Flow

**Components Involved:**
- `modules/logger.py` (`SecurityLogger` class)
- `modules/database.py` (`DatabaseManager` class - accessed via `db` alias)
- `logs/security.log` (log file)

**Sequence of Operations:**
1. **Initialization (`SecurityLogger.__init__`):**
   - During application startup (likely from `main.py`), an instance of `SecurityLogger` is created.
   - `setup_file_logger` is called, which creates the `logs` directory if it doesn't exist and configures Python's `logging` module to write to `logs/security.log` and the console.
2. **Event Triggering (Various Modules):**
   - Throughout the application, security-relevant events (e.g., user login, key generation, file encryption, errors) trigger calls to `security_logger.log_activity`.
   - Examples include: `AuthManager.register_user`, `KeyManager.create_user_keys`, `FileCrypto.encrypt_file`, `SignatureVerification.verify_signature`, etc.
3. **`SecurityLogger.log_activity` (`modules/logger.py`):**
   - **Database Logging:** Attempts to insert a log record into the `activity_logs` table in the SQLite database via `db.execute_query`.
     - Stores `user_id`, `action`, `status`, `details`, `ip_address`, and `email`.
     - Includes error handling for database logging failures.
   - **File Logging:** Formats the log message into a universal string format (`Email:<user_email> Action:<action> Status:<status> Details:<detail>`) and writes it to `logs/security.log` and the console using Python's `logging` module. The log level (INFO, WARNING, ERROR) is determined by the `status` of the activity.
   - **Parameters:** It accepts `user_id` (optional), `action` (required), `status` (default: 'success'), `details` (optional), `ip_address` (default: '127.0.0.1'), and `email` (optional but recommended for user actions).

### 1.2. Log Retrieval and Display Flow

**Components Involved:**
- `gui/tabs/admin_tab.py` (`AdminTab` class)
- `modules/logger.py` (`SecurityLogger` class)
- `modules/database.py` (`DatabaseManager` class - accessed via `db` alias)

**Sequence of Operations:**
1. **Admin Views Logs:** From `AdminTab`, the administrator clicks the "View System Logs" button.
2. **`AdminTab.view_system_logs`:**
   - Calls `db.get_all_activity_logs(limit=50)` (from `DatabaseManager`) to retrieve the most recent security logs from the database.
   - Formats the retrieved log data into a human-readable text block.
   - Displays the formatted logs in an `InfoDialog`.
3. **`SecurityLogger.get_logs` (Called by `DatabaseManager` in `db.get_all_activity_logs`):**
   - Executes a SQL query to select records from the `activity_logs` table, ordered by timestamp, with an optional `user_id` filter and `limit`.
   - Returns the fetched log records.

## 2. How to Use the Feature

### 2.1. System-wide Audit Logging (Automatic)
- All security-relevant actions and events within the application are automatically logged. Users do not need to manually trigger logging.
- These logs are stored in the application's database and a plain text file (`logs/security.log`).

### 2.2. Viewing Security Logs (Admin Only)
1. Log in to the application with an account that has the `admin` role.
2. Navigate to the "Admin" tab.
3. In the "Admin Dashboard" section (or a similar area), click the "View System Logs" button.
4. A dialog box will appear displaying a list of recent system activities, including timestamps, associated user emails, actions performed, statuses (success/failure/info), and additional details.

## 3. Technical Knowledge about Security

### 3.1. Comprehensive Logging of Security Events
- **Mechanism:** The application logs a wide array of security-relevant events, including:
  - User authentication (login, logout, registration, recovery).
  - Key management (generation, encryption, decryption, renewal).
  - File operations (encryption, decryption).
  - Digital signature operations (signing, verification).
  - Errors and exceptions related to security functions.
- **Purpose:** Creates a detailed audit trail that allows administrators to monitor system activity, detect suspicious behavior, investigate security incidents, and ensure accountability. It provides forensic data crucial for post-incident analysis.
- **Relevance to Best Practices:** Comprehensive logging is a cornerstone of any secure system. It supports principles of accountability, detectability, and non-repudiation.

### 3.2. Dual Logging (Database and File System)
- **Mechanism:** Log entries are simultaneously stored in two locations:
  - **SQLite Database (`activity_logs` table):** Provides structured storage for easy querying and reporting within the application (e.g., for the Admin tab).
  - **Plain Text File (`logs/security.log`):** Offers a raw, human-readable record that can be easily reviewed by system administrators or external tools, even if the database is inaccessible or corrupted. It also provides a chronological, append-only record.
- **Purpose:** Increases the resilience of the audit trail. If one logging mechanism fails or is compromised, the other might still retain critical information. It provides redundancy and flexibility for log analysis.
- **Relevance to Best Practices:** Dual logging enhances the robustness of audit trails, crucial for maintaining data availability and integrity in security monitoring.

### 3.3. Standardized Log Format
- **Mechanism:** Logs are formatted consistently with key information: `timestamp`, `level`, `user_id`, `action`, `status`, `details`, and `email`. The file-based logs use a universal format `[Time] Email:<user_email> Action:<action> Status:<status> Details:<detail>`.
- **Purpose:** Ensures consistency and ease of parsing for automated analysis or manual review. A standardized format is vital for effective log management and correlation of events across different system components.
- **Relevance to Best Practices:** Uniform logging formats are essential for effective security information and event management (SIEM) and for efficient incident response processes.

### 3.4. Administrator-Specific Log Access
- **Mechanism:** Access to view system audit logs through the GUI is restricted to users with the `admin` role, enforced by role-based access control (as detailed in the RBAC documentation).
- **Purpose:** Protects sensitive audit data from unauthorized viewing, ensuring that only trusted personnel can review security events. This prevents an attacker from hiding their tracks by deleting or modifying log entries if they gain basic user access.
- **Relevance to Best Practices:** Implementing least privilege for log access is critical. Logs often contain sensitive information about system behavior and potential security incidents, requiring strict access controls. 