from flask import Blueprint, request, jsonify, session
from backend.database.connection import db_manager
from backend.security.hasher import password_service
from backend.security.adaptive_engine import adaptive_engine
from backend.security.captcha_service import captcha_service

auth_bp = Blueprint('auth_bp', __name__)

@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json() or {}
    full_name = data.get('fullName', '').strip()
    email = data.get('email', '').strip().lower()
    username = data.get('username', '').strip()
    password = data.get('password', '')

    if not full_name or not email or not username or not password:
        return jsonify({'success': False, 'message': 'All registration fields are required.'}), 400

    # Strong password validation
    is_valid, msg = password_service.validate_password_strength(password)
    if not is_valid:
        return jsonify({'success': False, 'message': msg}), 400

    # Prevent duplicates
    existing = db_manager.query(
        "SELECT id FROM users WHERE username = %s OR email = %s LIMIT 1;",
        (username, email), fetch_one=True
    )
    if existing:
        return jsonify({'success': False, 'message': 'Username or Email is already registered.'}), 409

    # Cryptographically hash password (Argon2 / Bcrypt)
    hashed = password_service.hash_password(password)

    db_manager.query('''
        INSERT INTO users (full_name, username, email, password_hash, role, status, failed_attempts)
        VALUES (%s, %s, %s, %s, 'Standard User', 'Active', 0);
    ''', (full_name, username, email, hashed), commit=True)

    # Audit log entry
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr or '127.0.0.1')
    db_manager.query('''
        INSERT INTO audit_logs (actor_username, action, target_resource, details, ip_address)
        VALUES (%s, 'USER_REGISTERED', 'users', 'Account registered with cryptographic hash', %s);
    ''', (username, client_ip), commit=True)

    return jsonify({'success': True, 'message': 'Account registered securely.'}), 201

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    username = data.get('username', '').strip()
    password = data.get('password', '')
    captcha_answer = data.get('captcha', '').strip()
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr or '127.0.0.1')
    user_agent = request.headers.get('User-Agent', 'Unknown Client')

    if not username or not password:
        return jsonify({'success': False, 'message': 'Username and password are required.'}), 400

    # 1. Pre-flight Adaptive Threat Assessment
    pre_flight = adaptive_engine.evaluate_pre_login(username, client_ip, user_agent)
    if not pre_flight['allowed']:
        return jsonify({
            'success': False,
            'message': pre_flight['reason'],
            'status': pre_flight['status'],
            'risk_score': pre_flight['risk_score'],
            'remaining_seconds': pre_flight.get('remaining_seconds', 600)
        }), 403

    # 2. CAPTCHA Verification if enforced
    if pre_flight['require_captcha']:
        if not captcha_answer:
            res = adaptive_engine.process_failed_attempt(username, client_ip, user_agent, "CAPTCHA verification required but missing")
            http_code = 403 if res['status'] in ('ACCOUNT_LOCKED', 'IP_BLOCKED') else 400
            return jsonify({
                'success': False,
                'require_captcha': True,
                'message': f"Adaptive security: {res['action_taken']}" if res['status'] == 'ACCOUNT_LOCKED' else 'Adaptive security: CAPTCHA verification required.',
                'status': res['status'],
                'risk_score': res['risk_score']
            }), http_code

        if not captcha_service.verify_challenge(client_ip, captcha_answer):
            res = adaptive_engine.process_failed_attempt(username, client_ip, user_agent, "CAPTCHA challenge verification failed")
            http_code = 403 if res['status'] in ('ACCOUNT_LOCKED', 'IP_BLOCKED') else 400
            return jsonify({
                'success': False,
                'require_captcha': True,
                'message': 'Incorrect CAPTCHA answer code.',
                'status': res['status'],
                'risk_score': res['risk_score']
            }), http_code

    # 3. Retrieve User Record
    user = db_manager.query(
        "SELECT * FROM users WHERE username = %s OR email = %s LIMIT 1;",
        (username, username.lower()), fetch_one=True
    )

    # 4. Timing-attack safe password verification
    is_valid_password = False
    if user:
        is_valid_password = password_service.verify_password(password, user['password_hash'])

    if not is_valid_password:
        res = adaptive_engine.process_failed_attempt(username, client_ip, user_agent, "Invalid password credentials")
        http_code = 403 if res['status'] in ('ACCOUNT_LOCKED', 'IP_BLOCKED') else 401
        return jsonify({
            'success': False,
            'message': f"Account locked: {res['action_taken']}" if res['status'] == 'ACCOUNT_LOCKED' else 'Invalid username or password credentials.',
            'status': res['status'],
            'risk_score': res['risk_score'],
            'action_taken': res['action_taken'],
            'require_captcha': res['status'] == 'CAPTCHA_TRIGGERED'
        }), http_code

    # 5. Success Flow
    adaptive_engine.process_successful_attempt(user, client_ip, user_agent)
    session['user_id'] = user['id']
    session['username'] = user['username']
    session['role'] = user['role']

    # Audit log
    db_manager.query('''
        INSERT INTO audit_logs (actor_username, action, target_resource, details, ip_address)
        VALUES (%s, 'LOGIN_SUCCESS', 'user_sessions', 'Successful adaptive authentication', %s);
    ''', (user['username'], client_ip), commit=True)

    return jsonify({
        'success': True,
        'message': 'Authentication approved.',
        'user': {
            'username': user['username'],
            'role': user['role'],
            'email': user['email']
        }
    })

@auth_bp.route('/captcha', methods=['GET'])
def get_captcha():
    mode = request.args.get('mode', 'alphanumeric')
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr or '127.0.0.1')
    challenge_data = captcha_service.generate_challenge(client_ip, mode=mode)
    return jsonify({
        'success': True,
        'challenge': challenge_data['challenge'],
        'mode': challenge_data['mode']
    })

@auth_bp.route('/captcha/verify', methods=['POST'])
def verify_captcha():
    data = request.get_json() or {}
    answer = data.get('answer', '').strip()
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr or '127.0.0.1')
    is_valid = captcha_service.verify_challenge(client_ip, answer)
    return jsonify({'success': is_valid, 'verified': is_valid})

@auth_bp.route('/me', methods=['GET'])
def current_user():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'authenticated': False}), 401
    user = db_manager.query("SELECT id, username, full_name, email, role, status FROM users WHERE id = %s;", (user_id,), fetch_one=True)
    if not user:
        session.clear()
        return jsonify({'authenticated': False}), 401
    return jsonify({'authenticated': True, 'user': user})

@auth_bp.route('/logout', methods=['POST'])
def logout():
    username = session.get('username', 'Anonymous')
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr or '127.0.0.1')
    session.clear()

    db_manager.query('''
        INSERT INTO audit_logs (actor_username, action, target_resource, details, ip_address)
        VALUES (%s, 'LOGOUT', 'user_sessions', 'User session terminated', %s);
    ''', (username, client_ip), commit=True)

    return jsonify({'success': True, 'message': 'Logged out securely.'})
