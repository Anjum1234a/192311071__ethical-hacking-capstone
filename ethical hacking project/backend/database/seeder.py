import datetime
import random
from backend.database.connection import db_manager

def seed_database_if_empty(hasher_func):
    """Populates database with realistic cybersecurity telemetry and default accounts."""
    # 1. Security Settings
    setting_cnt = db_manager.query("SELECT COUNT(*) as c FROM security_settings;", fetch_one=True)['c']
    if setting_cnt == 0:
        db_manager.query('''
            INSERT INTO security_settings 
            (id, max_failed_attempts, attempt_window_minutes, lockout_duration_minutes, suspicious_risk_threshold, captcha_trigger_threshold, auto_ip_blocking, ip_block_threshold, ip_block_duration_minutes, notifications_enabled)
            VALUES (1, 5, 5, 10, 50, 3, 1, 8, 60, 1);
        ''', commit=True)

    # 2. Users Table
    user_cnt = db_manager.query("SELECT COUNT(*) as c FROM users;", fetch_one=True)['c']
    if user_cnt == 0:
        default_users = [
            ('System Administrator', 'admin', 'admin@sentinel.ai', hasher_func('Admin@1234'), 'Administrator', 'Active', 0),
            ('Security Analyst', 'sec_analyst', 'analyst@sentinel.ai', hasher_func('Analyst@1234'), 'Security Analyst', 'Active', 0),
            ('Threat Hunter', 'threat_hunter', 'hunter@sentinel.ai', hasher_func('Hunter@1234'), 'Security Analyst', 'Active', 0),
            ('Demonstration User', 'demo', 'demo@sentinel.ai', hasher_func('DemoPass123!'), 'Standard User', 'Active', 0),
            ('Finance Controller', 'finance_mgr', 'finance@sentinel.ai', hasher_func('FinancePass123!'), 'Standard User', 'Locked', 5)
        ]
        for u in default_users:
            db_manager.query('''
                INSERT INTO users (full_name, username, email, password_hash, role, status, failed_attempts)
                VALUES (%s, %s, %s, %s, %s, %s, %s);
            ''', u, commit=True)

    # 3. Blocked IPs Table
    ip_cnt = db_manager.query("SELECT COUNT(*) as c FROM blocked_ips;", fetch_one=True)['c']
    if ip_cnt == 0:
        blocked_data = [
            ('45.154.255.89', 'High-frequency brute-force dictionary attack', 48, 48, 98, 'Blocked'),
            ('185.220.101.5', 'Repeated credential stuffing across multiple accounts', 32, 31, 89, 'Blocked'),
            ('194.26.29.112', 'Automated script probing administrator endpoints', 26, 26, 92, 'Blocked'),
            ('91.240.118.234', 'Rapid POST burst on /api/auth/login', 64, 64, 100, 'Blocked')
        ]
        now = datetime.datetime.now()
        for b in blocked_data:
            expires = (now + datetime.timedelta(hours=1)).strftime('%Y-%m-%d %H:%M:%S')
            db_manager.query('''
                INSERT INTO blocked_ips (ip_address, reason, total_attempts, failed_attempts, risk_score, status, expires_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s);
            ''', (*b, expires), commit=True)

    # 4. Security Alerts Table
    alert_cnt = db_manager.query("SELECT COUNT(*) as c FROM security_alerts;", fetch_one=True)['c']
    if alert_cnt == 0:
        alerts = [
            ('ALT-8841', 'Brute-Force Attack Blocked', '45.154.255.89', 'root', 'CRITICAL', 'IP Auto-Banned for 60 min', 'Blocked'),
            ('ALT-8840', 'Multiple Failed Logins', '185.220.101.5', 'finance_mgr', 'WARNING', 'Adaptive CAPTCHA Enforced', 'Challenged'),
            ('ALT-8839', 'Account Lockout', '109.205.213.6', 'alex_turner', 'CRITICAL', 'Account Locked for 10 min', 'Active'),
            ('ALT-8838', 'Suspicious IP Anomaly', '198.51.100.23', 'dev_ops', 'WARNING', 'Risk Score Raised to 45%', 'Investigating'),
            ('ALT-8837', 'Geo-Velocity Anomaly', '103.24.12.8', 'sarah_k', 'INFO', '2FA Verification Requested', 'Resolved')
        ]
        for a in alerts:
            db_manager.query('''
                INSERT INTO security_alerts (alert_code, event_type, ip_address, username, risk_level, action_taken, status)
                VALUES (%s, %s, %s, %s, %s, %s, %s);
            ''', a, commit=True)

    # 5. Seed Historical Login Attempts for Charts
    log_cnt = db_manager.query("SELECT COUNT(*) as c FROM login_attempts;", fetch_one=True)['c']
    if log_cnt == 0:
        now = datetime.datetime.now()
        sample_attempts = [
            (1, 'admin', '192.168.1.45', 'Chrome 122 / Windows 11', 'SUCCESS', 5, None, (now - datetime.timedelta(minutes=2)).strftime('%Y-%m-%d %H:%M:%S')),
            (2, 'sec_analyst', '103.21.244.12', 'Firefox 124 / macOS', 'SUCCESS', 12, None, (now - datetime.timedelta(minutes=8)).strftime('%Y-%m-%d %H:%M:%S')),
            (3, 'threat_hunter', '185.220.101.5', 'Python-requests/2.31', 'FAILED', 65, 'Credential mismatch', (now - datetime.timedelta(minutes=14)).strftime('%Y-%m-%d %H:%M:%S')),
            (None, 'root', '45.154.255.89', 'Hydra v9.5 Brute-Force', 'IP_BLOCKED', 98, 'Dictionary attack probe', (now - datetime.timedelta(minutes=19)).strftime('%Y-%m-%d %H:%M:%S')),
            (4, 'demo', '49.36.128.4', 'Safari / iOS 17', 'SUCCESS', 8, None, (now - datetime.timedelta(minutes=25)).strftime('%Y-%m-%d %H:%M:%S')),
            (5, 'finance_mgr', '185.220.101.5', 'Python-requests/2.31', 'CAPTCHA_TRIGGERED', 58, 'Excessive attempts', (now - datetime.timedelta(minutes=32)).strftime('%Y-%m-%d %H:%M:%S')),
            (None, 'dev_ops', '198.51.100.23', 'Curl / 8.4.0', 'FAILED', 45, 'Wrong password', (now - datetime.timedelta(minutes=41)).strftime('%Y-%m-%d %H:%M:%S'))
        ]
        for a in sample_attempts:
            db_manager.query('''
                INSERT INTO login_attempts (user_id, username, ip_address, user_agent, status, risk_score, failure_reason, attempted_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s);
            ''', a, commit=True)

