from flask import Blueprint, request, jsonify
from backend.database.connection import db_manager
from backend.security.hasher import password_service
from backend.security.adaptive_engine import adaptive_engine

accounts_bp = Blueprint('accounts_bp', __name__)

@accounts_bp.route('', methods=['GET'])
def list_accounts():
    search = request.args.get('search', '').strip().lower()

    sql = '''
        SELECT u.id, u.full_name as name, u.username, u.email, u.role, u.status, u.failed_attempts as failedAttempts,
               (SELECT attempted_at FROM login_attempts WHERE username = u.username ORDER BY id DESC LIMIT 1) as lastLogin
        FROM users u
        ORDER BY u.id ASC;
    '''
    rows = db_manager.query(sql, fetch_all=True)

    if search:
        rows = [
            r for r in rows 
            if search in r['name'].lower() 
            or search in r['username'].lower() 
            or search in r['email'].lower()
        ]

    for r in rows:
        if not r['lastLogin']:
            r['lastLogin'] = 'Never'
        else:
            r['lastLogin'] = str(r['lastLogin'])

    return jsonify({'success': True, 'users': rows})

@accounts_bp.route('/create', methods=['POST'])
def create_account():
    data = request.get_json() or {}
    full_name = data.get('name', '').strip()
    username = data.get('username', '').strip()
    email = data.get('email', '').strip().lower()
    role = data.get('role', 'Standard User')
    password = data.get('password', 'DefaultSecPass123!')

    if not full_name or not username or not email:
        return jsonify({'success': False, 'message': 'All user fields are required.'}), 400

    existing = db_manager.query("SELECT id FROM users WHERE username = %s OR email = %s LIMIT 1;", (username, email), fetch_one=True)
    if existing:
        return jsonify({'success': False, 'message': 'User with this username or email already exists.'}), 409

    hashed = password_service.hash_password(password)

    user_id = db_manager.query('''
        INSERT INTO users (full_name, username, email, password_hash, role, status, failed_attempts)
        VALUES (%s, %s, %s, %s, %s, 'Active', 0);
    ''', (full_name, username, email, hashed, role), commit=True)

    return jsonify({
        'success': True,
        'message': f'User {username} created successfully.',
        'userId': user_id
    }), 201

@accounts_bp.route('/unlock', methods=['POST'])
def unlock_account():
    data = request.get_json() or {}
    user_id = data.get('userId')
    username = data.get('username')

    if not user_id and not username:
        return jsonify({'success': False, 'message': 'User identifier required.'}), 400

    if user_id:
        user = db_manager.query("SELECT * FROM users WHERE id = %s LIMIT 1;", (user_id,), fetch_one=True)
    else:
        user = db_manager.query("SELECT * FROM users WHERE username = %s LIMIT 1;", (username,), fetch_one=True)

    if not user:
        return jsonify({'success': False, 'message': 'User account not found.'}), 404

    adaptive_engine.unlock_user_account(user['id'], unlocked_by="Admin Command Center")
    return jsonify({'success': True, 'message': f"Account [{user['username']}] unlocked and brute-force counters cleared."})

@accounts_bp.route('/lock', methods=['POST'])
def lock_account():
    data = request.get_json() or {}
    user_id = data.get('userId')
    if not user_id:
        return jsonify({'success': False, 'message': 'User ID required.'}), 400

    db_manager.query("UPDATE users SET status = 'Locked', failed_attempts = 5 WHERE id = %s;", (user_id,), commit=True)
    return jsonify({'success': True, 'message': 'User placed under defensive lockout.'})

@accounts_bp.route('/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json() or {}
    username = data.get('username', '').strip()
    if not username:
        return jsonify({'success': False, 'message': 'Username required.'}), 400

    new_temp_pass = "ResetP@ss2026!"
    hashed = password_service.hash_password(new_temp_pass)

    db_manager.query("UPDATE users SET password_hash = %s, failed_attempts = 0, status = 'Active' WHERE username = %s;", (hashed, username), commit=True)
    return jsonify({
        'success': True,
        'message': f'Password hash regenerated for @{username}. Temporary credentials assigned: {new_temp_pass}'
    })

