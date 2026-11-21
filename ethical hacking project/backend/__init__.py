import os
from flask import Flask, render_template, jsonify
from flask_cors import CORS
from backend.config import AppConfig
from backend.database.schema import initialize_database_schema
from backend.database.seeder import seed_database_if_empty
from backend.security.hasher import password_service
from backend.middleware.security_headers import add_security_headers

# Import Blueprints
from backend.routes.auth_routes import auth_bp
from backend.routes.dashboard_routes import dashboard_bp
from backend.routes.realtime_routes import realtime_bp
from backend.routes.analytics_routes import analytics_bp
from backend.routes.ip_routes import ip_bp
from backend.routes.alerts_routes import alerts_bp
from backend.routes.accounts_routes import accounts_bp
from backend.routes.settings_routes import settings_bp
from backend.routes.history_routes import history_bp

def create_app():
    """Application Factory for SentinelShield Cybersecurity Backend."""
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    template_dir = os.path.join(base_dir, 'templates')
    static_dir = os.path.join(base_dir, 'static')

    app = Flask(__name__, template_folder=template_dir, static_folder=static_dir)
    app.config.from_object(AppConfig)
    
    # Cross-Origin Resource Sharing
    CORS(app)

    # Attach Security Headers Middleware
    app.after_request(add_security_headers)

    # Initialize and Seed Database
    initialize_database_schema()
    seed_database_if_empty(password_service.hash_password)

    # Register API Blueprints
    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(dashboard_bp, url_prefix='/api/dashboard')
    app.register_blueprint(realtime_bp, url_prefix='/api/realtime')
    app.register_blueprint(analytics_bp, url_prefix='/api/analytics')
    app.register_blueprint(ip_bp, url_prefix='/api/ip-monitoring')
    app.register_blueprint(alerts_bp, url_prefix='/api/alerts')
    app.register_blueprint(accounts_bp, url_prefix='/api/accounts')
    app.register_blueprint(settings_bp, url_prefix='/api/settings')
    app.register_blueprint(history_bp, url_prefix='/api/history')

    # Root Health API
    @app.route('/api/health', methods=['GET'])
    def health_check():
        from backend.database.connection import db_manager
        return jsonify({
            'status': 'healthy',
            'engine': 'SentinelShield Adaptive Engine 2.4.0',
            'hasher': 'Argon2id + Bcrypt Dual Engine',
            'db_mode': 'MySQL' if db_manager.use_mysql else 'SQLite-Embedded',
            'version': '2.4.0'
        })

    # =========================================================================
    # HTML PAGE ROUTES (All 12 Views)
    # =========================================================================
    @app.route('/')
    @app.route('/index.html')
    def page_index():
        return render_template('index.html')

    @app.route('/register')
    @app.route('/register.html')
    def page_register():
        return render_template('register.html')

    @app.route('/login')
    @app.route('/login.html')
    def page_login():
        return render_template('login.html')

    @app.route('/dashboard')
    @app.route('/dashboard.html')
    def page_dashboard():
        return render_template('dashboard.html')

    @app.route('/realtime')
    @app.route('/realtime.html')
    def page_realtime():
        return render_template('realtime.html')

    @app.route('/analytics')
    @app.route('/analytics.html')
    def page_analytics():
        return render_template('analytics.html')

    @app.route('/ip-monitoring')
    @app.route('/ip_monitoring.html')
    def page_ip_monitoring():
        return render_template('ip_monitoring.html')

    @app.route('/captcha')
    @app.route('/captcha.html')
    def page_captcha():
        return render_template('captcha.html')

    @app.route('/alerts')
    @app.route('/alerts.html')
    def page_alerts():
        return render_template('alerts.html')

    @app.route('/login-history')
    @app.route('/login_history.html')
    def page_login_history():
        return render_template('login_history.html')

    @app.route('/accounts')
    @app.route('/accounts.html')
    def page_accounts():
        return render_template('accounts.html')

    @app.route('/settings')
    @app.route('/settings.html')
    def page_settings():
        return render_template('settings.html')

    return app

