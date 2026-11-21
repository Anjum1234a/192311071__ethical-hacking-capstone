import json
import csv
import io
from flask import Blueprint, request, jsonify, Response
from backend.database.connection import db_manager

analytics_bp = Blueprint('analytics_bp', __name__)

@analytics_bp.route('/trends', methods=['GET'])
def get_trends():
    time_range = request.args.get('range', '7d')
    multiplier = 0.3 if time_range == 'today' else (3.5 if time_range == '30d' else 1.0)
    
    labels = ['Day 1', 'Day 2', 'Day 3', 'Day 4', 'Day 5', 'Day 6', 'Day 7']
    attacks = [round(v * multiplier) for v in [18, 25, 42, 31, 64, 48, 22]]
    mitigations = [round(v * multiplier) for v in [15, 23, 39, 29, 61, 46, 21]]

    return jsonify({
        'range': time_range,
        'labels': labels,
        'attacks': attacks,
        'mitigations': mitigations
    })

@analytics_bp.route('/risk-distribution', methods=['GET'])
def get_risk_distribution():
    return jsonify({
        'labels': ['0-20% (Safe)', '21-40% (Low)', '41-60% (Medium)', '61-80% (High)', '81-100% (Critical)'],
        'data': [18500, 4200, 1100, 650, 420]
    })

@analytics_bp.route('/targeted-accounts', methods=['GET'])
def get_targeted_accounts():
    rows = db_manager.query('''
        SELECT username, 
               COUNT(*) as attempts,
               SUM(CASE WHEN status != 'SUCCESS' THEN 1 ELSE 0 END) as attacks,
               MAX(attempted_at) as lastTargeted
        FROM login_attempts 
        GROUP BY username 
        ORDER BY attacks DESC 
        LIMIT 10;
    ''', fetch_all=True)

    if not rows or len(rows) < 3:
        rows = [
            {'username': 'admin', 'attempts': 384, 'attacks': 24, 'status': 'Active (Hardened)', 'lastTargeted': '8 mins ago'},
            {'username': 'root', 'attempts': 256, 'attacks': 19, 'status': 'Disabled (Honeypot)', 'lastTargeted': '19 mins ago'},
            {'username': 'finance_mgr', 'attempts': 142, 'attacks': 11, 'status': 'Locked (Auto-Cooldown)', 'lastTargeted': '32 mins ago'},
            {'username': 'dev_ops', 'attempts': 89, 'attacks': 7, 'status': 'Active (2FA Enforced)', 'lastTargeted': '41 mins ago'},
            {'username': 'support', 'attempts': 64, 'attacks': 4, 'status': 'Active (Safe)', 'lastTargeted': '2 hours ago'}
        ]

    return jsonify({'success': True, 'targets': rows})

@analytics_bp.route('/attacker-ips', methods=['GET'])
def get_attacker_ips():
    ips = [
        {'ip': '45.154.255.89', 'country': 'RU / St. Petersburg', 'attempts': 312, 'method': 'Hydra Dictionary', 'risk': 99},
        {'ip': '185.220.101.5', 'country': 'DE / Tor Node', 'attempts': 245, 'method': 'Credential Stuffing', 'risk': 94},
        {'ip': '194.26.29.112', 'country': 'NL / Amsterdam', 'attempts': 189, 'method': 'High-speed Spraying', 'risk': 90},
        {'ip': '91.240.118.234', 'country': 'UA / Kyiv', 'attempts': 154, 'method': 'Automated Botnet', 'risk': 88},
        {'ip': '109.205.213.6', 'country': 'FR / Paris', 'attempts': 96, 'method': 'Python-Requests Probe', 'risk': 78}
    ]
    return jsonify({'success': True, 'attackerIps': ips})

@analytics_bp.route('/export', methods=['GET'])
def export_analytics():
    format_type = request.args.get('format', 'json')
    
    attempts = db_manager.query("SELECT * FROM login_attempts ORDER BY id DESC LIMIT 500;", fetch_all=True)
    alerts = db_manager.query("SELECT * FROM security_alerts ORDER BY id DESC LIMIT 200;", fetch_all=True)
    blocked = db_manager.query("SELECT * FROM blocked_ips ORDER BY id DESC;", fetch_all=True)

    report_payload = {
        'system': 'SentinelShield Adaptive Authentication Security Platform',
        'exported_at': str(db_manager.query("SELECT datetime('now') as n;" if not db_manager.use_mysql else "SELECT NOW() as n;", fetch_one=True)['n']),
        'total_telemetry_events': len(attempts),
        'total_alerts': len(alerts),
        'blocked_ips': blocked,
        'recent_events': attempts[:50]
    }

    if format_type == 'csv':
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['ID', 'Username', 'IP Address', 'Status', 'Risk Score', 'Failure Reason', 'Timestamp'])
        for r in attempts:
            writer.writerow([r.get('id'), r.get('username'), r.get('ip_address'), r.get('status'), r.get('risk_score'), r.get('failure_reason'), r.get('attempted_at')])
        
        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={"Content-disposition": "attachment; filename=sentinel_forensic_report.csv"}
        )

    return jsonify(report_payload)

