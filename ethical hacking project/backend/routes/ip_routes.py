from flask import Blueprint, request, jsonify
from backend.database.connection import db_manager
from backend.security.adaptive_engine import adaptive_engine

ip_bp = Blueprint('ip_bp', __name__)

@ip_bp.route('', methods=['GET'])
def list_ips():
    search = request.args.get('search', '').strip().lower()
    status = request.args.get('status', 'all').strip()
    page = max(1, int(request.args.get('page', 1)))
    page_size = max(1, int(request.args.get('page_size', 10)))

    # Fetch IP aggregations
    sql = '''
        SELECT ip_address as ip,
               COUNT(*) as total,
               SUM(CASE WHEN status != 'SUCCESS' THEN 1 ELSE 0 END) as failed,
               SUM(CASE WHEN status = 'SUCCESS' THEN 1 ELSE 0 END) as success,
               MAX(risk_score) as risk,
               MAX(attempted_at) as lastActivity
        FROM login_attempts
        GROUP BY ip_address
    '''
    rows = db_manager.query(sql, fetch_all=True)

    # Cross-reference with blocked_ips table
    blocked_ips_db = {b['ip_address']: b for b in db_manager.query("SELECT * FROM blocked_ips;", fetch_all=True)}

    formatted = []
    seen_ips = set()

    for r in rows:
        ip = r['ip']
        seen_ips.add(ip)
        is_blocked = (ip in blocked_ips_db and blocked_ips_db[ip]['status'] == 'Blocked')
        curr_status = 'Blocked' if is_blocked else ('Suspicious' if r['risk'] >= 45 else 'Safe')

        formatted.append({
            'ip': ip,
            'total': r['total'],
            'failed': r['failed'],
            'success': r['success'],
            'risk': r['risk'],
            'status': curr_status,
            'lastActivity': r['lastActivity'] or 'Recently'
        })

    # Include any blocked IPs not in login_attempts
    for ip, b in blocked_ips_db.items():
        if ip not in seen_ips:
            formatted.append({
                'ip': ip,
                'total': b.get('total_attempts', 1),
                'failed': b.get('failed_attempts', 1),
                'success': 0,
                'risk': b.get('risk_score', 99),
                'status': b.get('status', 'Blocked'),
                'lastActivity': b.get('blocked_at', 'Recently')
            })

    # Filter by search
    if search:
        formatted = [i for i in formatted if search in i['ip'].lower()]

    # Filter by status
    if status != 'all':
        formatted = [i for i in formatted if i['status'].lower() == status.lower()]

    # Sort: Blocked first, then highest risk
    formatted.sort(key=lambda x: (x['status'] == 'Blocked', x['risk']), reverse=True)

    total_count = len(formatted)
    total_pages = max(1, (total_count + page_size - 1) // page_size)
    start_idx = (page - 1) * page_size
    paged_items = formatted[start_idx:start_idx + page_size]

    return jsonify({
        'success': True,
        'items': paged_items,
        'total': total_count,
        'pages': total_pages,
        'current_page': page
    })

@ip_bp.route('/block', methods=['POST'])
def block_ip():
    data = request.get_json() or {}
    ip = data.get('ip', '').strip()
    reason = data.get('reason', 'Manual Administrator Enforcement')
    duration = int(data.get('duration', 120))

    if not ip:
        return jsonify({'success': False, 'message': 'IP address is required.'}), 400

    adaptive_engine.manually_quarantine_ip(ip, reason, duration)
    return jsonify({'success': True, 'message': f'IP {ip} has been quarantined.'})

@ip_bp.route('/unblock', methods=['POST'])
def unblock_ip():
    data = request.get_json() or {}
    ip = data.get('ip', '').strip()
    if not ip:
        return jsonify({'success': False, 'message': 'IP address is required.'}), 400

    adaptive_engine.unblock_ip(ip)
    return jsonify({'success': True, 'message': f'IP {ip} has been unblocked.'})

