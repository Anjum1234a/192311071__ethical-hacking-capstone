from flask import Blueprint, request, jsonify
from backend.database.connection import db_manager

alerts_bp = Blueprint('alerts_bp', __name__)

@alerts_bp.route('', methods=['GET'])
def list_alerts():
    severity = request.args.get('severity', 'ALL').upper()
    search = request.args.get('search', '').strip().lower()

    sql = "SELECT * FROM security_alerts WHERE 1=1"
    params = []

    if severity != 'ALL':
        sql += " AND risk_level = %s"
        params.append(severity)

    sql += " ORDER BY id DESC LIMIT 100;"
    rows = db_manager.query(sql, tuple(params), fetch_all=True)

    formatted = []
    for r in rows:
        formatted.append({
            'id': r.get('alert_code') or f"ALT-{r.get('id')}",
            'db_id': r.get('id'),
            'type': r.get('event_type'),
            'ip': r.get('ip_address'),
            'username': r.get('username') or 'N/A',
            'risk': r.get('risk_level'),
            'action': r.get('action_taken'),
            'status': r.get('status', 'Active'),
            'timestamp': str(r.get('created_at'))
        })

    if search:
        formatted = [
            a for a in formatted 
            if search in a['id'].lower() 
            or search in a['type'].lower() 
            or search in a['ip'].lower() 
            or search in a['username'].lower()
        ]

    return jsonify({'success': True, 'alerts': formatted})

@alerts_bp.route('/<alert_id>/resolve', methods=['POST'])
def resolve_alert(alert_id):
    db_manager.query('''
        UPDATE security_alerts SET status = 'Resolved' 
        WHERE alert_code = %s OR id = %s;
    ''', (alert_id, alert_id), commit=True)
    return jsonify({'success': True, 'message': f'Alert {alert_id} resolved.'})

@alerts_bp.route('/<alert_id>/dismiss', methods=['POST'])
def dismiss_alert(alert_id):
    db_manager.query('''
        DELETE FROM security_alerts 
        WHERE alert_code = %s OR id = %s;
    ''', (alert_id, alert_id), commit=True)
    return jsonify({'success': True, 'message': f'Alert {alert_id} dismissed.'})

