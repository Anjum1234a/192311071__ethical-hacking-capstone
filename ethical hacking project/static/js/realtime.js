/**
 * Adaptive Authentication Security System (AASS)
 * Real-Time Attack Monitoring Controller
 */

window.AASS_Realtime = {
    isPaused: false,
    pollInterval: null,
    logCount: 0,

    init: function() {
        AASS_Realtime.renderLiveFeed();
        AASS_Realtime.bindControls();
        AASS_Realtime.startAutoStream();

        // Listen for simulation events
        window.addEventListener('aass:event', (e) => {
            if (e.detail && e.detail.activity) {
                AASS_Realtime.appendActivityItem(e.detail.activity);
                AASS_Realtime.addTerminalLine(e.detail.activity);
                AASS_Realtime.spawnRadarBlip();
            }
        });
    },

    bindControls: function() {
        const pauseBtn = document.getElementById('btn-pause-stream');
        if (pauseBtn) {
            pauseBtn.addEventListener('click', () => {
                AASS_Realtime.isPaused = !AASS_Realtime.isPaused;
                pauseBtn.innerHTML = AASS_Realtime.isPaused ? 
                    `<i data-lucide="play"></i> Resume Feed` : 
                    `<i data-lucide="pause"></i> Pause Feed`;
                pauseBtn.className = AASS_Realtime.isPaused ? 'btn-secondary-custom btn-sm-custom' : 'btn-primary-custom btn-sm-custom';
                AASS.initLucide();
                AASS.showToast(AASS_Realtime.isPaused ? 'Live monitoring paused.' : 'Live monitoring resumed.', 'info');
            });
        }

        const clearBtn = document.getElementById('btn-clear-terminal');
        if (clearBtn) {
            clearBtn.addEventListener('click', () => {
                const terminal = document.getElementById('terminal-logs');
                if (terminal) terminal.innerHTML = '<div class="text-muted text-xs">// Terminal output cleared. Listening for incoming packets...</div>';
            });
        }
    },

    startAutoStream: function() {
        // Stream subtle background ambient traffic if not simulating
        AASS_Realtime.pollInterval = setInterval(() => {
            if (AASS_Realtime.isPaused || AASS_Simulator.isRunning) return;

            // 35% chance per tick to generate ambient normal user traffic
            if (Math.random() < 0.35) {
                const mockUsers = ['sarah_k', 'finance_mgr', 'alex_turner', 'sec_analyst', 'dev_ops', 'threat_hunter'];
                const user = mockUsers[Math.floor(Math.random() * mockUsers.length)];
                const isFail = Math.random() < 0.2; // 20% natural typo failure
                const ip = '103.21.' + Math.floor(Math.random() * 255) + '.' + Math.floor(Math.random() * 255);
                
                const item = {
                    id: Date.now(),
                    username: user,
                    ip: ip,
                    status: isFail ? 'FAILED' : 'SUCCESS',
                    risk: isFail ? Math.floor(Math.random() * 25 + 20) : Math.floor(Math.random() * 12),
                    time: 'Just now',
                    location: 'Normal User Session',
                    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
                };

                AASS.data.recentActivity.unshift(item);
                if (AASS.data.recentActivity.length > 50) AASS.data.recentActivity.pop();

                AASS_Realtime.appendActivityItem(item);
                AASS_Realtime.addTerminalLine(item);
            }
        }, 3000);
    },

    renderLiveFeed: async function() {
        const streamContainer = document.getElementById('live-stream-container');
        if (!streamContainer) return;

        if (AASS.isLiveBackend) {
            try {
                const res = await fetch(`${AASS.apiBase}/realtime/logs`);
                if (res.ok) {
                    const data = await res.json();
                    if (data.logs && data.logs.length > 0) {
                        AASS.data.recentActivity = data.logs;
                    }
                }
            } catch (e) {}
        }

        streamContainer.innerHTML = '';
        AASS.data.recentActivity.slice(0, 10).forEach(item => {
            AASS_Realtime.appendActivityItem(item, false);
            AASS_Realtime.addTerminalLine(item);
        });
    },

    appendActivityItem: function(item, prepend = true) {
        const container = document.getElementById('live-stream-container');
        if (!container) return;

        let badgeClass = 'badge-safe';
        let statusTitle = 'Authentication Approved';
        if (item.status === 'FAILED') { badgeClass = 'badge-danger'; statusTitle = 'Credential Mismatch'; }
        if (item.status === 'CAPTCHA_TRIGGERED') { badgeClass = 'badge-suspicious'; statusTitle = 'CAPTCHA Challenge Triggered'; }
        if (item.status === 'ACCOUNT_LOCKED') { badgeClass = 'badge-blocked'; statusTitle = 'Account Temporarily Locked'; }
        if (item.status === 'IP_BLOCKED' || item.status === 'BLOCKED') { badgeClass = 'badge-blocked'; statusTitle = 'Attacker IP Blacklisted'; }

        const card = document.createElement('div');
        card.className = 'card-custom p-3 mb-2 animate-fade-in';
        card.style.borderLeft = item.risk > 70 ? '4px solid var(--danger-red)' : (item.risk > 40 ? '4px solid var(--warning-orange)' : '4px solid var(--success-green)');
        
        card.innerHTML = `
            <div class="d-flex justify-content-between align-items-center mb-1">
                <div class="d-flex align-items-center gap-2">
                    <span class="badge-status ${badgeClass}">${item.status}</span>
                    <strong class="text-sm font-semibold text-dark">${item.username}</strong>
                </div>
                <span class="text-xs text-muted">${item.time}</span>
            </div>
            <div class="d-flex justify-content-between align-items-center text-xs text-secondary mt-2">
                <span>Source IP: <code class="bg-slate-100 px-1 py-0.5 rounded text-dark">${item.ip}</code></span>
                <span>Risk: <strong style="color: ${item.risk > 70 ? 'var(--danger-red)' : (item.risk > 40 ? 'var(--warning-orange)' : 'var(--success-green)')};">${item.risk}%</strong></span>
            </div>
            <div class="text-xs text-muted mt-1">
                Agent: ${item.userAgent}
            </div>
        `;

        if (prepend) {
            container.insertBefore(card, container.firstChild);
            if (container.children.length > 25) {
                container.removeChild(container.lastChild);
            }
        } else {
            container.appendChild(card);
        }
    },

    addTerminalLine: function(item) {
        const terminal = document.getElementById('terminal-logs');
        if (!terminal) return;

        const time = new Date().toLocaleTimeString();
        let colorClass = 'terminal-type-success';
        if (item.status === 'FAILED') colorClass = 'terminal-type-warn';
        if (item.status.includes('CAPTCHA')) colorClass = 'terminal-type-warn';
        if (item.status.includes('BLOCKED') || item.status.includes('LOCKED')) colorClass = 'terminal-type-danger';

        const line = document.createElement('div');
        line.className = 'terminal-line';
        line.innerHTML = `
            <span class="terminal-time">[${time}]</span>
            <span class="${colorClass}">[${item.status}]</span>
            <span>SRC: ${item.ip} &rarr; USER: ${item.username} (Risk: ${item.risk}%)</span>
        `;

        terminal.appendChild(line);
        terminal.scrollTop = terminal.scrollHeight;
    },

    spawnRadarBlip: function() {
        const radar = document.querySelector('.radar-box');
        if (!radar) return;

        const blip = document.createElement('div');
        blip.className = 'radar-blip';
        
        // Random position inside radar circle
        const angle = Math.random() * Math.PI * 2;
        const radius = Math.random() * 80;
        const x = 100 + radius * Math.cos(angle) - 5;
        const y = 100 + radius * Math.sin(angle) - 5;

        blip.style.left = `${x}px`;
        blip.style.top = `${y}px`;

        radar.appendChild(blip);
        setTimeout(() => blip.remove(), 2500);
    }
};

document.addEventListener('DOMContentLoaded', () => {
    AASS_Realtime.init();
});

