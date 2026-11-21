import datetime
import random
from backend.database.connection import db_manager
from backend.security.hasher import password_service
from backend.security.captcha_service import captcha_service

class RealTimeAdaptiveSecurityEngine:
    """
    Module 2: Real-Time Brute-Force Attack Detection & Prevention
    Threat Defense Subsystem
    
    Core Adaptive Cybersecurity Engine:
    - Real-Time Heuristic Ingestion & Telemetry
    - Dynamic Anomaly Risk Scoring (0–100%)
    - Sliding Window Attack Burst Identification
    - Multi-Tier Escalation:
        Tier 1: Frictionless Approval (Risk < 40%)
        Tier 2: Intermediate Dynamic CAPTCHA Challenge (Failed >= 3 or Risk >= 50%)
        Tier 3: Automated Account Defensive Lockout (Failed >= 5, Cooldown: 10m)
        Tier 4: Automated Source IP Quarantine & Isolation (IP Burst >= 8, Cooldown: 60m)
    - High-Priority Alert Dispatch
    """

    def __init__(self):
        self.listeners = [] # Callbacks for live SSE / WebSocket broadcast

    def register_listener(self, callback):
        self.listeners.append(callback)

    def broadcast_event(self, event_type: str, data: dict):
        """Notify real-time dashboards of incoming security telemetry."""
        payload = {
            'event': event_type,
            'timestamp': datetime.datetime.now().strftime('%H:%M:%S'),
            'data': data
        }
        for cb in list(self.listeners):
            try:
                cb(payload)
            except Exception:
                pass

    def get_settings(self) -> dict:
        """Fetch real-time configurable security thresholds from database."""
        row = db_manager.query("SELECT * FROM security_settings LIMIT 1;", fetch_one=True)
        if not row:
            return {
                'max_failed_attempts': 5,
                'attempt_window_minutes': 5,
                'lockout_duration_minutes': 10,
                'suspicious_risk_threshold': 50,
                'captcha_trigger_threshold': 3,
                'auto_ip_blocking': 1,
                'ip_block_threshold': 8,
                'ip_block_duration_minutes': 60,
                'notifications_enabled': 1
            }
        return row

    def update_settings(self, new_settings: dict):
        """Updates parameters with immediate application by the backend engine."""
        db_manager.query('''
            UPDATE security_settings SET 
                max_failed_attempts = %s,
                attempt_window_minutes = %s,
                lockout_duration_minutes = %s,
                suspicious_risk_threshold = %s,
                captcha_trigger_threshold = %s,
                auto_ip_blocking = %s,
                ip_block_threshold = %s,
                notifications_enabled = %s
            WHERE id = 1;
        ''', (
            new_settings.get('maxFailedAttempts', 5),
            new_settings.get('windowMinutes', 5),
            new_settings.get('lockoutMinutes', 10),
            new_settings.get('suspiciousThreshold', 50),
            new_settings.get('captchaThreshold', 3),
            1 if new_settings.get('autoBlockIp', True) else 0,
            new_settings.get('ipBlockThreshold', 8),
            1 if new_settings.get('notificationsEnabled', True) else 0
        ), commit=True)

        self.broadcast_event('SETTINGS_UPDATED', new_settings)

    def is_ip_blocked(self, ip_address: str) -> tuple[bool, str]:
        """Validates if source IP is actively quarantined."""
        row = db_manager.query(
            "SELECT * FROM blocked_ips WHERE ip_address = %s AND status = 'Blocked' LIMIT 1;",
            (ip_address,), fetch_one=True
        )
        if not row:
            return False, ""

        # Check expiration
        if row.get('expires_at'):
            try:
                expires_at = datetime.datetime.fromisoformat(str(row['expires_at']))
                if datetime.datetime.now() > expires_at:
                    db_manager.query("UPDATE blocked_ips SET status = 'Expired' WHERE id = %s;", (row['id'],), commit=True)
                    return False, ""
            except Exception:
                pass
        return True, row.get('reason', 'IP Quarantined due to brute-force attack.')

    def is_account_locked(self, username: str) -> tuple[bool, int]:
        """Validates whether account is under defensive cooldown."""
        user = db_manager.query("SELECT * FROM users WHERE username = %s LIMIT 1;", (username,), fetch_one=True)
        if not user or user.get('status') != 'Locked':
            return False, 0

        lockout = db_manager.query('''
            SELECT * FROM account_lockouts 
            WHERE user_id = %s AND is_unlocked = 0 
            ORDER BY id DESC LIMIT 1;
        ''', (user['id'],), fetch_one=True)

        if not lockout:
            return False, 0

        expires_at_str = str(lockout['lockout_expires_at'])
        try:
            expires_at = datetime.datetime.fromisoformat(expires_at_str)
            now = datetime.datetime.now()
            if now < expires_at:
                remaining_sec = int((expires_at - now).total_seconds())
                return True, max(1, remaining_sec)
            else:
                # Automatic cooldown expired
                self.unlock_user_account(user['id'], unlocked_by="Automatic Cooldown Expiration")
                return False, 0
        except Exception:
            return True, 300

    def calculate_risk_score(self, username: str, ip_address: str, user_agent: str = '') -> int:
        """
        Calculates dynamic risk score (0 to 100%):
        - IP attempt velocity in sliding window
        - Username target attempt velocity in sliding window
        - User-Agent known attack tool heuristics (Hydra, Burp, Python-requests, Curl, Sqlmap)
        """
        settings = self.get_settings()
        window_minutes = settings.get('attempt_window_minutes', 5)
        now = datetime.datetime.now()
        window_start = (now - datetime.timedelta(minutes=window_minutes)).strftime('%Y-%m-%d %H:%M:%S')

        # IP failure count
        ip_fail_res = db_manager.query('''
            SELECT COUNT(*) as c FROM login_attempts 
            WHERE ip_address = %s AND status != 'SUCCESS' AND attempted_at >= %s;
        ''', (ip_address, window_start), fetch_one=True)
        ip_fail_cnt = ip_fail_res['c'] if ip_fail_res else 0

        # User failure count
        user_fail_res = db_manager.query('''
            SELECT COUNT(*) as c FROM login_attempts 
            WHERE username = %s AND status != 'SUCCESS' AND attempted_at >= %s;
        ''', (username, window_start), fetch_one=True)
        user_fail_cnt = user_fail_res['c'] if user_fail_res else 0

        # Anomaly scoring
        base_risk = (ip_fail_cnt * 16) + (user_fail_cnt * 18)

        # Attacker tool signature detection
        ua_lower = (user_agent or '').lower()
        if any(tool in ua_lower for tool in ['hydra', 'burp', 'sqlmap', 'nmap', 'metasploit', 'nikto']):
            base_risk += 45
        elif any(script in ua_lower for script in ['python-requests', 'curl', 'postman', 'aiohttp', 'go-http']):
            base_risk += 20

        return min(99, max(0, base_risk))

    def evaluate_pre_login(self, username: str, ip_address: str, user_agent: str = '') -> dict:
        """
        Pre-flight risk assessment executed BEFORE reading or verifying password.
        """
        settings = self.get_settings()

        # 1. IP Block Quarantine Check
        is_blocked, block_reason = self.is_ip_blocked(ip_address)
        if is_blocked:
            return {
                'allowed': False,
                'require_captcha': False,
                'reason': block_reason or 'Source IP address is quarantined due to detected brute-force attacks.',
                'risk_score': 100,
                'status': 'IP_BLOCKED'
            }

        # 2. Account Lockout Check
        is_locked, remaining_seconds = self.is_account_locked(username)
        if is_locked:
            minutes = remaining_seconds // 60
            seconds = remaining_seconds % 60
            return {
                'allowed': False,
                'require_captcha': False,
                'reason': f'Account is under defensive lockout. Cooldown remaining: {minutes}m {seconds:02d}s.',
                'risk_score': 95,
                'status': 'ACCOUNT_LOCKED',
                'remaining_seconds': remaining_seconds
            }

        # 3. Dynamic Risk Score
        risk_score = self.calculate_risk_score(username, ip_address, user_agent)

        # 4. CAPTCHA Trigger Condition
        user = db_manager.query("SELECT failed_attempts FROM users WHERE username = %s LIMIT 1;", (username,), fetch_one=True)
        user_failed = user['failed_attempts'] if user else 0
        require_captcha = (user_failed >= settings['captcha_trigger_threshold']) or (risk_score >= settings['suspicious_risk_threshold'])

        return {
            'allowed': True,
            'require_captcha': require_captcha,
            'reason': 'Pre-flight security check passed.',
            'risk_score': risk_score,
            'status': 'OK'
        }

    def process_failed_attempt(self, username: str, ip_address: str, user_agent: str, failure_reason: str):
        """
        Adaptive Security Response triggered on incorrect credentials or failed CAPTCHA.
        Updates counters, evaluates thresholds, enforces account lockout, and auto-quarantines rogue IPs.
        """
        settings = self.get_settings()
        now = datetime.datetime.now()
        risk_score = min(99, self.calculate_risk_score(username, ip_address, user_agent) + 20)

        user = db_manager.query("SELECT * FROM users WHERE username = %s LIMIT 1;", (username,), fetch_one=True)
        user_id = user['id'] if user else None
        current_failed = (user['failed_attempts'] if user else 0) + 1

        status = 'FAILED'
        action_taken = 'Failed attempt logged'
        alert_generated = None

        if user:
            db_manager.query("UPDATE users SET failed_attempts = %s WHERE id = %s;", (current_failed, user['id']), commit=True)

        # Tier 2 Escalation: CAPTCHA Trigger Threshold
        if current_failed == settings['captcha_trigger_threshold']:
            status = 'CAPTCHA_TRIGGERED'
            action_taken = 'Dynamic CAPTCHA Challenge Enforced'
            alert_generated = {
                'code': f"ALT-{random.randint(1000, 9999)}",
                'type': 'Multiple Failed Login Attempts',
                'ip': ip_address,
                'username': username,
                'risk': 'WARNING',
                'action': action_taken
            }

        # Tier 3 Escalation: Account Lockout Threshold
        elif current_failed >= settings['max_failed_attempts']:
            status = 'ACCOUNT_LOCKED'
            lock_duration = settings['lockout_duration_minutes']
            expires_at = (now + datetime.timedelta(minutes=lock_duration)).strftime('%Y-%m-%d %H:%M:%S')

            if user:
                db_manager.query("UPDATE users SET status = 'Locked' WHERE id = %s;", (user['id'],), commit=True)
                db_manager.query('''
                    INSERT INTO account_lockouts (user_id, username, locked_ip, failed_attempts_count, lockout_expires_at)
                    VALUES (%s, %s, %s, %s, %s);
                ''', (user['id'], username, ip_address, current_failed, expires_at), commit=True)

            action_taken = f"Account Locked for {lock_duration} minutes"
            alert_generated = {
                'code': f"ALT-{random.randint(1000, 9999)}",
                'type': 'Possible Brute-Force: Account Locked',
                'ip': ip_address,
                'username': username,
                'risk': 'CRITICAL',
                'action': action_taken
            }

        # Tier 4 Escalation: IP-Wide Brute Force Auto-Quarantine
        if settings['auto_ip_blocking']:
            window_start = (now - datetime.timedelta(minutes=settings['attempt_window_minutes'])).strftime('%Y-%m-%d %H:%M:%S')
            ip_count_res = db_manager.query('''
                SELECT COUNT(*) as c FROM login_attempts 
                WHERE ip_address = %s AND attempted_at >= %s;
            ''', (ip_address, window_start), fetch_one=True)
            total_ip_attempts = (ip_count_res['c'] if ip_count_res else 0) + 1

            if total_ip_attempts >= settings['ip_block_threshold']:
                status = 'IP_BLOCKED'
                block_duration = settings.get('ip_block_duration_minutes', 60)
                expires_at = (now + datetime.timedelta(minutes=block_duration)).strftime('%Y-%m-%d %H:%M:%S')

                # Upsert blocked_ips
                existing_ip = db_manager.query("SELECT id FROM blocked_ips WHERE ip_address = %s;", (ip_address,), fetch_one=True)
                if existing_ip:
                    db_manager.query('''
                        UPDATE blocked_ips SET 
                            status = 'Blocked',
                            failed_attempts = failed_attempts + 1,
                            total_attempts = total_attempts + 1,
                            expires_at = %s
                        WHERE ip_address = %s;
                    ''', (expires_at, ip_address), commit=True)
                else:
                    db_manager.query('''
                        INSERT INTO blocked_ips (ip_address, reason, total_attempts, failed_attempts, risk_score, status, expires_at)
                        VALUES (%s, %s, %s, %s, %s, 'Blocked', %s);
                    ''', (ip_address, 'Automated Real-Time Brute-Force Quarantine', total_ip_attempts, total_ip_attempts, 99, expires_at), commit=True)

                action_taken = f"Source IP auto-banned for {block_duration} minutes"
                alert_generated = {
                    'code': f"ALT-{random.randint(1000, 9999)}",
                    'type': 'Brute-Force Attack: IP Quarantined',
                    'ip': ip_address,
                    'username': username,
                    'risk': 'CRITICAL',
                    'action': action_taken
                }

        # Record login attempt
        db_manager.query('''
            INSERT INTO login_attempts (user_id, username, ip_address, user_agent, status, risk_score, failure_reason)
            VALUES (%s, %s, %s, %s, %s, %s, %s);
        ''', (user_id, username, ip_address, user_agent, status, risk_score, failure_reason), commit=True)

        # Record alert if generated
        if alert_generated:
            db_manager.query('''
                INSERT INTO security_alerts (alert_code, event_type, ip_address, username, risk_level, action_taken, status)
                VALUES (%s, %s, %s, %s, %s, %s, 'Active');
            ''', (
                alert_generated['code'],
                alert_generated['type'],
                alert_generated['ip'],
                alert_generated['username'],
                alert_generated['risk'],
                alert_generated['action']
            ), commit=True)

        event_data = {
            'username': username,
            'ip': ip_address,
            'status': status,
            'risk_score': risk_score,
            'action_taken': action_taken,
            'alert': alert_generated
        }
        self.broadcast_event('LOGIN_FAILED', event_data)

        return event_data

    def process_successful_attempt(self, user: dict, ip_address: str, user_agent: str):
        """Resets failed counters and logs successful authentication."""
        db_manager.query("UPDATE users SET failed_attempts = 0, status = 'Active' WHERE id = %s;", (user['id'],), commit=True)
        db_manager.query('''
            INSERT INTO login_attempts (user_id, username, ip_address, user_agent, status, risk_score, failure_reason)
            VALUES (%s, %s, %s, %s, 'SUCCESS', 5, NULL);
        ''', (user['id'], user['username'], ip_address, user_agent), commit=True)

        event_data = {
            'username': user['username'],
            'ip': ip_address,
            'status': 'SUCCESS',
            'risk_score': 5
        }
        self.broadcast_event('LOGIN_SUCCESS', event_data)

    def unlock_user_account(self, user_id: int, unlocked_by: str = "Administrator"):
        """Clears account lockout and restores active state."""
        now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        db_manager.query("UPDATE users SET status = 'Active', failed_attempts = 0 WHERE id = %s;", (user_id,), commit=True)
        db_manager.query('''
            UPDATE account_lockouts SET is_unlocked = 1, unlocked_at = %s, unlocked_by = %s
            WHERE user_id = %s AND is_unlocked = 0;
        ''', (now, unlocked_by, user_id), commit=True)

        self.broadcast_event('ACCOUNT_UNLOCKED', {'user_id': user_id, 'unlocked_by': unlocked_by})

    def manually_quarantine_ip(self, ip_address: str, reason: str = "Manual Administrator Enforcement", duration_minutes: int = 120):
        """Immediately blocks an IP address with expiration."""
        now = datetime.datetime.now()
        expires_at = (now + datetime.timedelta(minutes=duration_minutes)).strftime('%Y-%m-%d %H:%M:%S')

        existing = db_manager.query("SELECT id FROM blocked_ips WHERE ip_address = %s;", (ip_address,), fetch_one=True)
        if existing:
            db_manager.query('''
                UPDATE blocked_ips SET status = 'Blocked', reason = %s, expires_at = %s
                WHERE ip_address = %s;
            ''', (reason, expires_at, ip_address), commit=True)
        else:
            db_manager.query('''
                INSERT INTO blocked_ips (ip_address, reason, total_attempts, failed_attempts, risk_score, status, expires_at)
                VALUES (%s, %s, 10, 10, 99, 'Blocked', %s);
            ''', (ip_address, reason, expires_at), commit=True)

        self.broadcast_event('IP_BLOCKED', {'ip': ip_address, 'reason': reason})

    def unblock_ip(self, ip_address: str):
        """Whitelists and restores quarantined IP."""
        db_manager.query("UPDATE blocked_ips SET status = 'Whitelisted' WHERE ip_address = %s;", (ip_address,), commit=True)
        self.broadcast_event('IP_UNBLOCKED', {'ip': ip_address})

adaptive_engine = RealTimeAdaptiveSecurityEngine()
