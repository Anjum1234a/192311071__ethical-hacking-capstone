import os
from dotenv import load_dotenv

load_dotenv()

class AppConfig:
    """Centralized Application & Cybersecurity System Configuration"""
    
    # Secret Key & Cryptographic Salt
    SECRET_KEY = os.getenv('SECRET_KEY', 'sentinel_shield_adaptive_auth_super_secret_2026_prod')
    
    # Session Cookie Security
    SESSION_COOKIE_NAME = 'sentinel_session'
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = 86400  # 24 hours
    
    # MySQL Production Database Parameters
    DB_HOST = os.getenv('DB_HOST', 'localhost')
    DB_USER = os.getenv('DB_USER', 'root')
    DB_PASSWORD = os.getenv('DB_PASSWORD', '')
    DB_NAME = os.getenv('DB_NAME', 'adaptive_auth_db')
    DB_PORT = int(os.getenv('DB_PORT', 3306))
    
    # Embedded SQLite Fallback Database
    BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    SQLITE_PATH = os.path.join(BASE_DIR, 'database.db')
    
    # Adaptive Security Engine Default Baseline Parameters
    DEFAULT_MAX_FAILED_ATTEMPTS = 5
    DEFAULT_WINDOW_MINUTES = 5
    DEFAULT_LOCKOUT_MINUTES = 10
    DEFAULT_SUSPICIOUS_THRESHOLD = 50
    DEFAULT_CAPTCHA_THRESHOLD = 3
    DEFAULT_AUTO_BLOCK_IP = True
    DEFAULT_IP_BLOCK_THRESHOLD = 8
    DEFAULT_IP_BLOCK_MINUTES = 60
    DEFAULT_NOTIFICATIONS_ENABLED = True

