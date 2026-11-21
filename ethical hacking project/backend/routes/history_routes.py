import io
import csv
from flask import Blueprint, request, jsonify, Response
from backend.database.connection import db_manager

history_bp = Blueprint('history_bp', __name__)

@history_bp.route('', methods=['GET'])
def get_login_history():
    search = request.args.get('search', '').strip().lower()
    status = request.args.get('status', 'all').strip()
    page = max(1, int(request.args.get('page', 1)))
    page_size = max(1, int(request.args.get('page_size', 10)))

    sql = '''
        SELECT id, username, ip_address as ip, status, risk_score as risk,
               attempted_at as time, user_agent as userAgent, failure_reason
        FROM login_attempts
        ORDER BY id DESC;
    '''
    rows = db_manager.query(sql, fetch_all=True)

    formatted = []
    for r in rows:
        formatted.append({
            'id': r['id'],
            'username': r['username'],
            'ip': r['ip'],
            'status': r['status'],
            'risk': r['risk'],
            'time': str(r['time']),
            'userAgent': r['userAgent'] or 'Standard Client Browser',
            'failureReason': r['failure_reason'] or 'N/A'
        })

    # Search filter
    if search:
        formatted = [
            r for r in formatted
            if search in r['username'].lower()
            or search in r['ip'].lower()
            or search in r['userAgent'].lower()
        ]

    # Status filter
    if status != 'all':
        formatted = [r for r in formatted if status.lower() in r['status'].lower()]

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

@history_bp.route('/export', methods=['GET'])
def export_history_csv():
    rows = db_manager.query('''
        SELECT id, username, ip_address as ip, status, risk_score as risk,
               attempted_at as time, user_agent as userAgent, failure_reason
        FROM login_attempts
        ORDER BY id DESC LIMIT 1000;
    ''', fetch_all=True)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'Username', 'IP Address', 'Status', 'Risk Score', 'User Agent', 'Failure Reason', 'Timestamp'])

    for r in rows:
        writer.writerow([r['id'], r['username'], r['ip'], r['status'], r['risk'], r['userAgent'], r['failure_reason'], r['time']])

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-disposition": "attachment; filename=aass_login_audit_trail.csv"}
    )

