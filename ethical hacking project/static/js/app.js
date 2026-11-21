/**
 * Adaptive Authentication Security System (AASS)
 * Core Application Framework & State Management
 */

// Shared State & Configuration
window.AASS = {
    version: "2.4.0",
    apiBase: "/api",
    isLiveBackend: false,
    currentUser: null,
    settings: {
        maxFailedAttempts: 5,
        windowMinutes: 5,
        lockoutMinutes: 10,
        suspiciousThreshold: 50,
        captchaThreshold: 3,
        autoBlockIp: true,
        ipBlockThreshold: 8,
        notificationsEnabled: true
    },
    // Seed initial mock forensic dataset for rich visual presentation
    data: {
        stats: {
            totalUsers: 1420,
            totalLogins: 28450,
            failedLogins: 1824,
            successLogins: 26626,
            detectedAttacks: 142,
            blockedIps: 18
        },
        recentActivity: [
            { id: 101, username: 'admin', ip: '192.168.1.45', status: 'SUCCESS', risk: 5, time: '2 mins ago', location: 'Internal / HQ (10.0.0.1)', userAgent: 'Chrome 122 / Windows 11' },
            { id: 102, username: 'sec_analyst', ip: '103.21.244.12', status: 'SUCCESS', risk: 12, time: '8 mins ago', location: 'Hyderabad, IN', userAgent: 'Firefox 124 / macOS' },
            { id: 103, username: 'threat_hunter', ip: '185.220.101.5', status: 'FAILED', risk: 65, time: '14 mins ago', location: 'Tor Exit Node / DE', userAgent: 'Python-requests/2.31' },
            { id: 104, username: 'root', ip: '45.154.255.89', status: 'BLOCKED', risk: 95, time: '19 mins ago', location: 'St. Petersburg, RU', userAgent: 'Hydra / v9.5 Brute-Force' },
            { id: 105, username: 'sarah_k', ip: '49.36.128.4', status: 'SUCCESS', risk: 8, time: '25 mins ago', location: 'Bangalore, IN', userAgent: 'Safari / iOS 17' },
            { id: 106, username: 'finance_mgr', ip: '185.220.101.5', status: 'CAPTCHA_TRIGGERED', risk: 58, time: '32 mins ago', location: 'Tor Exit Node / DE', userAgent: 'Python-requests/2.31' },
            { id: 107, username: 'dev_ops', ip: '198.51.100.23', status: 'FAILED', risk: 45, time: '41 mins ago', location: 'Amsterdam, NL', userAgent: 'Curl / 8.4.0' }
        ],
        alerts: [
            { id: 'ALT-8841', type: 'Brute-Force Detected', ip: '45.154.255.89', username: 'root', risk: 'CRITICAL', status: 'Blocked', action: 'IP Auto-Banned for 60 min', timestamp: '19 mins ago' },
            { id: 'ALT-8840', type: 'Multiple Failed Logins', ip: '185.220.101.5', username: 'finance_mgr', risk: 'WARNING', status: 'Challenged', action: 'Adaptive CAPTCHA Enforced', timestamp: '32 mins ago' },
            { id: 'ALT-8839', type: 'Account Lockout', ip: '109.205.213.6', username: 'alex_turner', risk: 'CRITICAL', status: 'Active Lock', action: 'Account Locked for 10 min', timestamp: '1 hour ago' },
            { id: 'ALT-8838', type: 'Suspicious IP Anomaly', ip: '198.51.100.23', username: 'dev_ops', risk: 'WARNING', status: 'Monitored', action: 'Risk Score Raised to 45%', timestamp: '2 hours ago' },
            { id: 'ALT-8837', type: 'Geo-Velocity Anomaly', ip: '103.24.12.8', username: 'sarah_k', risk: 'INFO', status: 'Resolved', action: '2FA Verification Requested', timestamp: '4 hours ago' }
        ],
        blockedIps: [
            { ip: '45.154.255.89', reason: 'High-frequency brute-force dictionary attack', attempts: 48, failed: 48, risk: 98, status: 'Blocked', blockedAt: 'Today, 10:01 AM', expiresAt: 'Today, 11:01 AM' },
            { ip: '185.220.101.5', reason: 'Repeated credential stuffing across multiple users', attempts: 32, failed: 31, risk: 89, status: 'Blocked', blockedAt: 'Today, 09:45 AM', expiresAt: 'Today, 10:45 AM' },
            { ip: '194.26.29.112', reason: 'Automated script probing admin accounts', attempts: 26, failed: 26, risk: 92, status: 'Blocked', blockedAt: 'Today, 08:30 AM', expiresAt: 'Today, 09:30 AM' },
            { ip: '91.240.118.234', reason: 'Rapid POST storm on /api/auth/login', attempts: 64, failed: 64, risk: 100, status: 'Blocked', blockedAt: 'Today, 07:15 AM', expiresAt: 'Today, 08:15 AM' }
        ],
        ipDirectory: [
            { ip: '192.168.1.45', total: 412, failed: 3, success: 409, risk: 5, status: 'Safe', lastActivity: '2 mins ago' },
            { ip: '103.21.244.12', total: 184, failed: 6, success: 178, risk: 12, status: 'Safe', lastActivity: '8 mins ago' },
            { ip: '185.220.101.5', total: 35, failed: 34, success: 1, risk: 89, status: 'Blocked', lastActivity: '14 mins ago' },
            { ip: '45.154.255.89', total: 48, failed: 48, success: 0, risk: 98, status: 'Blocked', lastActivity: '19 mins ago' },
            { ip: '49.36.128.4', total: 95, failed: 2, success: 93, risk: 8, status: 'Safe', lastActivity: '25 mins ago' },
            { ip: '198.51.100.23', total: 16, failed: 11, success: 5, risk: 48, status: 'Suspicious', lastActivity: '41 mins ago' },
            { ip: '109.205.213.6', total: 12, failed: 12, success: 0, risk: 72, status: 'Suspicious', lastActivity: '1 hour ago' }
        ]
    }
};

// Initialize UI & Icons
document.addEventListener('DOMContentLoaded', () => {
    AASS.initLucide();
    AASS.checkBackendHealth();
    AASS.initNavigation();
    AASS.restoreSession();
});

// Icon Initialization helper
AASS.initLucide = function() {
    if (window.lucide && typeof lucide.createIcons === 'function') {
        lucide.createIcons();
    }
};

// Check if Python Flask REST Backend is responding
AASS.checkBackendHealth = async function() {
    try {
        const response = await fetch(`${AASS.apiBase}/health`, { method: 'GET' });
        if (response.ok) {
            const data = await response.json();
            AASS.isLiveBackend = true;
            console.log('✅ Connected to live AASS Python Flask Security Backend:', data);
            const statusBadge = document.getElementById('engine-status-badge');
            if (statusBadge) {
                statusBadge.innerHTML = `<span class="pulse-indicator"></span> Live Adaptive Engine (${data.hasher || 'Argon2id'})`;
                statusBadge.className = 'badge-status badge-safe';
            }
            AASS.initSSE();
            AASS.fetchLiveStats();
        }
    } catch (e) {
        AASS.isLiveBackend = false;
        console.log('ℹ️ Running with client-side Adaptive Security Engine preview');
    }
};

// Real-Time Server-Sent Events (SSE) Listener
AASS.initSSE = function() {
    if (!window.EventSource) return;
    try {
        const evtSource = new EventSource(`${AASS.apiBase}/realtime/stream`);
        evtSource.onmessage = function(event) {
            try {
                const payload = JSON.parse(event.data);
                if (payload.event === 'LOGIN_FAILED') {
                    const d = payload.data;
                    const activity = {
                        id: Date.now(),
                        username: d.username,
                        ip: d.ip,
                        status: d.status,
                        risk: d.risk_score,
                        time: payload.timestamp,
                        userAgent: 'Threat Detection Feed',
                        location: 'Detected Node'
                    };
                    AASS.data.recentActivity.unshift(activity);
                    if (AASS.data.recentActivity.length > 50) AASS.data.recentActivity.pop();

                    if (d.status === 'ACCOUNT_LOCKED') {
                        AASS.data.stats.detectedAttacks++;
                        AASS.showToast(`Adaptive Lockout enforced for account [${d.username}]`, 'critical', 'Defensive Lockout');
                    } else if (d.status === 'IP_BLOCKED') {
                        AASS.data.stats.blockedIps++;
                        AASS.showToast(`Source IP [${d.ip}] auto-quarantined.`, 'danger', 'IP Blocked');
                    } else if (d.status === 'CAPTCHA_TRIGGERED') {
                        AASS.showToast(`Dynamic CAPTCHA Challenge enforced for [${d.username}]`, 'warning', 'Anti-Bot Trigger');
                    }

                    window.dispatchEvent(new CustomEvent('aass:event', { detail: { activity: activity, alert: d.alert } }));
                } else if (payload.event === 'LOGIN_SUCCESS') {
                    AASS.data.stats.totalLogins++;
                    AASS.data.stats.successLogins++;
                    window.dispatchEvent(new CustomEvent('aass:event', { detail: {} }));
                } else if (payload.event === 'ACCOUNT_UNLOCKED') {
                    AASS.showToast(`Account ID ${payload.data.user_id} unlocked by ${payload.data.unlocked_by}`, 'success', 'Account Unlocked');
                } else if (payload.event === 'IP_BLOCKED') {
                    AASS.data.stats.blockedIps++;
                    window.dispatchEvent(new CustomEvent('aass:event', { detail: {} }));
                }
            } catch (err) {}
        };
    } catch (e) {
        console.warn('SSE not supported or connection error');
    }
};

// Fetch live database statistics from backend
AASS.fetchLiveStats = async function() {
    try {
        const res = await fetch(`${AASS.apiBase}/dashboard/stats`);
        if (res.ok) {
            const stats = await res.json();
            AASS.data.stats = Object.assign(AASS.data.stats, stats);
            window.dispatchEvent(new CustomEvent('aass:event', { detail: {} }));
        }
    } catch (e) {}
};

// Navigation and mobile sidebar toggle
AASS.initNavigation = function() {
    const toggleBtn = document.getElementById('sidebar-toggle-btn');
    const sidebar = document.querySelector('.sidebar');
    const overlay = document.querySelector('.sidebar-overlay');

    if (toggleBtn && sidebar) {
        toggleBtn.addEventListener('click', () => {
            sidebar.classList.toggle('show');
            if (overlay) overlay.classList.toggle('show');
        });
    }

    if (overlay && sidebar) {
        overlay.addEventListener('click', () => {
            sidebar.classList.remove('show');
            overlay.classList.remove('show');
        });
    }
};

// Session Management
AASS.restoreSession = function() {
    const stored = localStorage.getItem('aass_user');
    if (stored) {
        try {
            AASS.currentUser = JSON.parse(stored);
            const userDisplay = document.getElementById('nav-user-name');
            if (userDisplay) userDisplay.textContent = AASS.currentUser.username || 'Administrator';
        } catch (e) {
            localStorage.removeItem('aass_user');
        }
    }
};

AASS.logout = function() {
    localStorage.removeItem('aass_user');
    AASS.currentUser = null;
    AASS.showToast('You have been logged out securely.', 'info');
    setTimeout(() => {
        window.location.href = 'login.html';
    }, 600);
};

// Toast Notifications System
AASS.showToast = function(message, type = 'info', title = null) {
    let container = document.getElementById('toast-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'toast-container';
        document.body.appendChild(container);
    }

    const toast = document.createElement('div');
    toast.className = 'toast-item';
    
    let iconName = 'info';
    let iconColor = 'var(--primary-blue)';
    if (type === 'success') { iconName = 'check-circle'; iconColor = 'var(--success-green)'; }
    if (type === 'warning') { iconName = 'alert-triangle'; iconColor = 'var(--warning-orange)'; }
    if (type === 'danger' || type === 'critical') { iconName = 'shield-alert'; iconColor = 'var(--danger-red)'; }

    const header = title ? `<strong style="display:block; margin-bottom:2px; font-size:0.875rem;">${title}</strong>` : '';

    toast.innerHTML = `
        <div style="color:${iconColor}; margin-top:2px;">
            <i data-lucide="${iconName}" style="width:20px; height:20px;"></i>
        </div>
        <div style="flex:1;">
            ${header}
            <div style="font-size:0.85rem; color:var(--text-main);">${message}</div>
        </div>
        <button type="button" style="background:none; border:none; cursor:pointer; color:var(--text-muted);" onclick="this.parentElement.remove()">
            <i data-lucide="x" style="width:16px; height:16px;"></i>
        </button>
    `;

    container.appendChild(toast);
    AASS.initLucide();

    // Play subtle alert tone for critical attacks
    if (type === 'critical' || type === 'danger') {
        AASS.playBeep(440, 0.15);
    }

    setTimeout(() => {
        if (toast.parentElement) {
            toast.style.opacity = '0';
            toast.style.transform = 'translateY(10px)';
            toast.style.transition = 'all 0.3s ease';
            setTimeout(() => toast.remove(), 300);
        }
    }, 4500);
};

// Web Audio API Sound Synthesizer (No MP3 dependencies needed)
AASS.playBeep = function(frequency = 440, duration = 0.1) {
    try {
        const audioCtx = new (window.AudioContext || window.webkitAudioContext)();
        const osc = audioCtx.createOscillator();
        const gain = audioCtx.createGain();
        osc.type = 'sine';
        osc.frequency.setValueAtTime(frequency, audioCtx.currentTime);
        gain.gain.setValueAtTime(0.08, audioCtx.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.001, audioCtx.currentTime + duration);
        osc.connect(gain);
        gain.connect(audioCtx.destination);
        osc.start();
        osc.stop(audioCtx.currentTime + duration);
    } catch (e) {
        // AudioContext not allowed or not supported
    }
};

// Team Modal Renderer
AASS.showTeamModal = function() {
    let modal = document.getElementById('teamModal');
    if (!modal) {
        modal = document.createElement('div');
        modal.id = 'teamModal';
        modal.className = 'modal fade';
        modal.tabIndex = -1;
        modal.innerHTML = `
            <div class="modal-dialog modal-dialog-centered modal-lg">
                <div class="modal-content card-custom" style="border-radius: 18px; overflow: hidden; border: 1px solid var(--border-color);">
                    <div class="modal-header" style="background: linear-gradient(135deg, #EFF6FF 0%, #F5F3FF 100%); border-bottom: 1px solid var(--border-color); padding: 1.25rem 1.75rem;">
                        <div>
                            <div class="badge-status badge-purple mb-1">Academic Cybersecurity Project</div>
                            <h5 class="modal-title font-bold text-lg mb-0" style="color: var(--text-main);">Project & Team Architecture</h5>
                        </div>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body p-4">
                        <div class="mb-4">
                            <h6 class="text-xs font-semibold uppercase tracking-wider text-muted mb-1">Project Title</h6>
                            <h4 class="font-bold text-primary mb-2" style="color: var(--primary-blue);">Adaptive Authentication Security System for Real-Time Brute-Force Attack Detection and Prevention</h4>
                            <p class="text-sm text-secondary mb-0">An enterprise-grade cybersecurity platform that dynamically calculates authentication risk, enforces adaptive CAPTCHA challenges, isolates malicious IP addresses, and prevents distributed brute-force attacks in real time.</p>
                        </div>
                        <div class="row g-3">
                            <div class="col-md-6">
                                <div class="card-custom p-3 h-100" style="border-left: 4px solid var(--primary-blue);">
                                    <div class="d-flex align-items-center justify-content-between mb-2">
                                        <span class="badge-status badge-info">Module 1</span>
                                        <span class="text-xs text-muted font-mono">Authentication Core</span>
                                    </div>
                                    <h5 class="font-bold text-dark mb-1">Adaptive User Authentication</h5>
                                    <div class="text-xs font-semibold text-primary mb-3">Identity Verification & Access Management</div>
                                    <ul class="text-xs text-secondary ps-3 mb-0" style="line-height: 1.8;">
                                        <li>Secure User Registration with validation</li>
                                        <li>Adaptive Login Interface & Password Hashing</li>
                                        <li>Active Session Management & Invalidation</li>
                                        <li>Forensic Login Monitoring & History Audit</li>
                                        <li>Configurable Security Thresholds Engine</li>
                                    </ul>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="card-custom p-3 h-100" style="border-left: 4px solid var(--accent-purple);">
                                    <div class="d-flex align-items-center justify-content-between mb-2">
                                        <span class="badge-status badge-purple">Module 2</span>
                                        <span class="text-xs text-muted font-mono">Defense Engine</span>
                                    </div>
                                    <h5 class="font-bold text-dark mb-1">Real-Time Threat Prevention</h5>
                                    <div class="text-xs font-semibold text-purple mb-3" style="color: var(--accent-purple);">Adaptive Brute-Force Detection & Quarantine</div>
                                    <ul class="text-xs text-secondary ps-3 mb-0" style="line-height: 1.8;">
                                        <li>Real-Time Attack Detection Engine</li>
                                        <li>Adaptive Dynamic Risk Scoring Algorithm</li>
                                        <li>Automated Dynamic CAPTCHA Verification</li>
                                        <li>Real-Time IP Tracking & Automated Blacklisting</li>
                                        <li>Automated Account Lockout & Threat Isolation</li>
                                        <li>Live WebSocket / Polling Security Monitoring</li>
                                    </ul>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="modal-footer" style="background: var(--bg-primary); border-top: 1px solid var(--border-color); padding: 0.85rem 1.75rem;">
                        <button type="button" class="btn-secondary-custom" data-bs-dismiss="modal">Close</button>
                        <a href="dashboard.html" class="btn-primary-custom">Launch System Dashboard</a>
                    </div>
                </div>
            </div>
        `;
        document.body.appendChild(modal);
        AASS.initLucide();
    }
    const bsModal = new bootstrap.Modal(modal);
    bsModal.show();
};

