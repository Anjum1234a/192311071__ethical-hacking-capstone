import json
import time
import queue
from flask import Blueprint, Response, request, jsonify
from backend.security.adaptive_engine import adaptive_engine
from backend.database.connection import db_manager

realtime_bp = Blueprint('realtime_bp', __name__)

# Real-time event subscription queues for connected browser tabs
event_subscribers = []

def sse_event_dispatcher(event_payload):
    """Broadcasts security events to all connected SSE clients."""
    msg = f"data: {json.dumps(event_payload)}\n\n"
    for q in list(event_subscribers):
        try:
            q.put_nowait(msg)
        except Exception:
            try:
                event_subscribers.remove(q)
            except ValueError:
                pass

# Register callback with the adaptive security engine
adaptive_engine.register_listener(sse_event_dispatcher)

@realtime_bp.route('/stream', methods=['GET'])
def event_stream():
    """
    Server-Sent Events (SSE) Endpoint for real-time frontend updates.
    Broadcasts on: login attempts, brute-force detections, account lockouts, IP blocks.
    """
    client_queue = queue.Queue(maxsize=100)
    event_subscribers.append(client_queue)

    def event_generator():
        # Initial handshake ping
        yield f"data: {json.dumps({'event': 'CONNECTED', 'timestamp': time.strftime('%H:%M:%S'), 'msg': 'SentinelShield SSE stream established.'})}\n\n"
        try:
            while True:
                try:
                    # Wait for next security event
                    data = client_queue.get(timeout=25)
                    yield data
                except queue.Empty:
                    # Keep-alive heartbeat ping every 25s
                    yield f": heartbeat\n\n"
        except GeneratorExit:
            if client_queue in event_subscribers:
                event_subscribers.remove(client_queue)

    response = Response(event_generator(), mimetype='text/event-stream')
    response.headers['Cache-Control'] = 'no-cache'
    response.headers['X-Accel-Buffering'] = 'no'
    response.headers['Connection'] = 'keep-alive'
    return response

@realtime_bp.route('/logs', methods=['GET'])
def get_terminal_logs():
    """Terminal packet inspection logs."""
    rows = db_manager.query('''
        SELECT id, username, ip_address as ip, status, risk_score as risk, 
               attempted_at as time, user_agent as userAgent, failure_reason
        FROM login_attempts 
        ORDER BY id DESC LIMIT 50;
    ''', fetch_all=True)
    return jsonify({'success': True, 'logs': rows})

@realtime_bp.route('/simulate', methods=['POST'])
def trigger_simulation():
    """
    Backend simulation endpoint allowing presentation demonstrations to trigger
    single attacks or attack waves on the real Python adaptive engine.
    """
    data = request.get_json() or {}
    sim_type = data.get('type', 'single_fail') # 'single_fail', 'success', 'wave', 'reset'
    username = data.get('username', 'admin')
    ip = data.get('ip', '45.154.255.89')
    user_agent = data.get('userAgent', 'Hydra v9.5 (Kali-Linux Brute-Force Script)')

    if sim_type == 'success':
        user = db_manager.query("SELECT * FROM users WHERE username = %s LIMIT 1;", (username,), fetch_one=True)
        if user:
            adaptive_engine.process_successful_attempt(user, ip, user_agent)
            return jsonify({'success': True, 'status': 'SUCCESS', 'message': f'Simulated valid login for {username}'})
        return jsonify({'success': False, 'message': 'User not found'}), 404

    elif sim_type == 'single_fail':
        res = adaptive_engine.process_failed_attempt(username, ip, user_agent, "Simulated brute-force credential probe")
        return jsonify({
            'success': True,
            'status': res['status'],
            'risk_score': res['risk_score'],
            'action_taken': res['action_taken'],
            'alert': res['alert']
        })

    elif sim_type == 'wave':
        # Simulate burst of 5 rapid dictionary attacks
        results = []
        attacker_ips = ['45.154.255.89', '185.220.101.5', '194.26.29.112', '91.240.118.234']
        passwords = ['123456', 'admin123', 'qwerty', 'letmein', 'password']
        
        for idx in range(5):
            curr_ip = attacker_ips[idx % len(attacker_ips)]
            res = adaptive_engine.process_failed_attempt(username, curr_ip, user_agent, f"Dictionary password probe: {passwords[idx]}")
            results.append(res)
            
        return jsonify({
            'success': True,
            'message': 'Attack wave simulated across multiple source IPs.',
            'count': len(results),
            'final_status': results[-1]['status']
        })

    elif sim_type == 'reset':
        db_manager.query("UPDATE users SET failed_attempts = 0, status = 'Active';", commit=True)
        db_manager.query("UPDATE blocked_ips SET status = 'Whitelisted';", commit=True)
        adaptive_engine.broadcast_event('SIMULATION_RESET', {'message': 'Telemetry reset to baseline'})
        return jsonify({'success': True, 'message': 'Simulation state reset.'})

    return jsonify({'success': False, 'message': 'Invalid simulation type'}), 400

