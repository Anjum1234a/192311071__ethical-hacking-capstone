import os
from backend.database.connection import db_manager

def initialize_database_schema():
    """Initializes and verifies the 8 core cybersecurity relational tables."""
    conn, db_type = db_manager.get_raw_connection()
    cursor = conn.cursor()
    try:
        if db_type == 'mysql':
            # Execute MySQL schema
            base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
            schema_path = os.path.join(base_dir, 'schema.sql')
            if os.path.exists(schema_path):
                with open(schema_path, 'r', encoding='utf-8') as f:
                    statements = f.read().split(';')
                    for stmt in statements:
                        cleaned = stmt.strip()
                        if cleaned:
                            try:
                                cursor.execute(cleaned)
                            except Exception:
                                pass
        else:
            # SQLite Enterprise Schema
            cursor.executescript('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    full_name TEXT NOT NULL,
                    username TEXT NOT NULL UNIQUE,
                    email TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    role TEXT DEFAULT 'Standard User',
                    status TEXT DEFAULT 'Active',
                    failed_attempts INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS security_settings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    max_failed_attempts INTEGER NOT NULL DEFAULT 5,
                    attempt_window_minutes INTEGER NOT NULL DEFAULT 5,
                    lockout_duration_minutes INTEGER NOT NULL DEFAULT 10,
                    suspicious_risk_threshold INTEGER NOT NULL DEFAULT 50,
                    captcha_trigger_threshold INTEGER NOT NULL DEFAULT 3,
                    auto_ip_blocking INTEGER NOT NULL DEFAULT 1,
                    ip_block_threshold INTEGER NOT NULL DEFAULT 8,
                    ip_block_duration_minutes INTEGER NOT NULL DEFAULT 60,
                    notifications_enabled INTEGER NOT NULL DEFAULT 1,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS login_attempts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NULL,
                    username TEXT NOT NULL,
                    ip_address TEXT NOT NULL,
                    user_agent TEXT NULL,
                    status TEXT NOT NULL,
                    risk_score INTEGER NOT NULL DEFAULT 0,
                    failure_reason TEXT NULL,
                    attempted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
                );

                CREATE TABLE IF NOT EXISTS security_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_code TEXT NOT NULL UNIQUE,
                    event_type TEXT NOT NULL,
                    ip_address TEXT NOT NULL,
                    username TEXT NULL,
                    risk_level TEXT NOT NULL,
                    action_taken TEXT NOT NULL,
                    status TEXT DEFAULT 'Active',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS blocked_ips (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT NOT NULL UNIQUE,
                    reason TEXT NOT NULL,
                    total_attempts INTEGER DEFAULT 1,
                    failed_attempts INTEGER DEFAULT 1,
                    risk_score INTEGER DEFAULT 99,
                    status TEXT DEFAULT 'Blocked',
                    blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP NULL
                );

                CREATE TABLE IF NOT EXISTS account_lockouts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    username TEXT NOT NULL,
                    locked_ip TEXT NOT NULL,
                    failed_attempts_count INTEGER NOT NULL,
                    locked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    lockout_expires_at TIMESTAMP NOT NULL,
                    is_unlocked INTEGER DEFAULT 0,
                    unlocked_at TIMESTAMP NULL,
                    unlocked_by TEXT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS user_sessions (
                    id TEXT PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    ip_address TEXT NOT NULL,
                    user_agent TEXT NULL,
                    is_active INTEGER DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_activity_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    actor_username TEXT NOT NULL,
                    action TEXT NOT NULL,
                    target_resource TEXT NULL,
                    details TEXT NULL,
                    ip_address TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                -- Indexes for High Velocity Attack Querying
                CREATE INDEX IF NOT EXISTS idx_login_ip ON login_attempts (ip_address, attempted_at);
                CREATE INDEX IF NOT EXISTS idx_login_user ON login_attempts (username, attempted_at);
                CREATE INDEX IF NOT EXISTS idx_alerts_risk ON security_alerts (risk_level);
                CREATE INDEX IF NOT EXISTS idx_blocked_ip_addr ON blocked_ips (ip_address);
            ''')
            conn.commit()
    finally:
        cursor.close()
        conn.close()

