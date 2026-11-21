import os
import sqlite3
import threading
from backend.config import AppConfig

try:
    import pymysql
    import pymysql.cursors
    HAS_PYMYSQL = True
except ImportError:
    HAS_PYMYSQL = False

class DatabaseConnectionManager:
    """
    Robust Dual-Engine Database Manager:
    - Primary: Enterprise MySQL Server
    - Fallback: High-Performance SQLite Embedded Engine (Zero-Config)
    """
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(DatabaseConnectionManager, cls).__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self.use_mysql = False
        self.sqlite_path = AppConfig.SQLITE_PATH
        self.check_and_initialize()
        self._initialized = True

    def check_and_initialize(self):
        """Detect database availability and prepare schema"""
        if HAS_PYMYSQL:
            try:
                test_conn = pymysql.connect(
                    host=AppConfig.DB_HOST,
                    user=AppConfig.DB_USER,
                    password=AppConfig.DB_PASSWORD,
                    port=AppConfig.DB_PORT,
                    connect_timeout=3
                )
                cursor = test_conn.cursor()
                cursor.execute(f"CREATE DATABASE IF NOT EXISTS `{AppConfig.DB_NAME}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;")
                test_conn.close()
                self.use_mysql = True
                print("[SUCCESS] MySQL server connected successfully.")
            except Exception as e:
                self.use_mysql = False
                print(f"[INFO] MySQL offline ({e}). Using SQLite embedded fallback: {self.sqlite_path}")
        else:
            self.use_mysql = False
            print(f"[INFO] PyMySQL unavailable. Using SQLite embedded database: {self.sqlite_path}")

    def get_raw_connection(self):
        """Obtain raw database connection based on active engine"""
        if HAS_PYMYSQL and self.use_mysql:
            try:
                conn = pymysql.connect(
                    host=AppConfig.DB_HOST,
                    user=AppConfig.DB_USER,
                    password=AppConfig.DB_PASSWORD,
                    database=AppConfig.DB_NAME,
                    port=AppConfig.DB_PORT,
                    cursorclass=pymysql.cursors.DictCursor,
                    autocommit=True
                )
                return conn, 'mysql'
            except Exception:
                self.use_mysql = False

        conn = sqlite3.connect(self.sqlite_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn, 'sqlite'

    def query(self, sql: str, params: tuple = (), fetch_one: bool = False, fetch_all: bool = False, commit: bool = False):
        """
        Execute parameterized SQL query with automatic placeholder translation.
        Safeguards against SQL injection vulnerabilities.
        """
        conn, db_type = self.get_raw_connection()
        cursor = conn.cursor()
        try:
            # SQLite uses ? while MySQL uses %s
            executable_sql = sql
            if db_type == 'sqlite':
                executable_sql = executable_sql.replace('%s', '?')

            cursor.execute(executable_sql, params)

            if commit:
                conn.commit()

            if fetch_one:
                row = cursor.fetchone()
                return dict(row) if row else None
            elif fetch_all:
                rows = cursor.fetchall()
                return [dict(r) for r in rows] if rows else []

            if commit:
                if db_type == 'sqlite':
                    return cursor.lastrowid
                else:
                    return cursor.lastrowid
            return None
        except Exception as err:
            if commit:
                conn.rollback()
            raise err
        finally:
            cursor.close()
            conn.close()

    # Alias for backward compatibility
    execute_query = query

db_manager = DatabaseConnectionManager()
