/**
 * Adaptive Authentication Security System (AASS)
 * Admin Dashboard Controller & Interactive Charts
 */

window.AASS_Dashboard = {
    charts: {},

    init: function() {
        AASS_Dashboard.renderStats();
        AASS_Dashboard.initCharts();
        AASS_Dashboard.loadLiveCharts();
        AASS_Dashboard.renderRecentActivity();
        AASS_Dashboard.renderRecentAlerts();
        AASS_Dashboard.renderSuspiciousIps();
        AASS_Dashboard.bindEvents();
    },

    bindEvents: function() {
        // Listen to live simulation or backend events
        window.addEventListener('aass:event', () => {
            AASS_Dashboard.renderStats();
            AASS_Dashboard.renderRecentActivity();
            AASS_Dashboard.renderRecentAlerts();
            AASS_Dashboard.updateCharts();
            AASS_Dashboard.loadLiveCharts();
        });

        window.addEventListener('aass:reset', () => {
            AASS_Dashboard.renderStats();
            AASS_Dashboard.renderRecentActivity();
            AASS_Dashboard.renderRecentAlerts();
            AASS_Dashboard.renderSuspiciousIps();
            AASS_Dashboard.initCharts();
            AASS_Dashboard.loadLiveCharts();
        });
    },

    // Render 6 KPI Metric Cards
    renderStats: function() {
        const s = AASS.data.stats;
        const setVal = (id, val) => {
            const el = document.getElementById(id);
            if (el) el.textContent = Number(val).toLocaleString();
        };

        setVal('stat-total-users', s.totalUsers);
        setVal('stat-total-logins', s.totalLogins);
        setVal('stat-failed-logins', s.failedLogins);
        setVal('stat-success-logins', s.successLogins);
        setVal('stat-detected-attacks', s.detectedAttacks);
        setVal('stat-blocked-ips', s.blockedIps);

        // Security Status indicator
        const secStatusEl = document.getElementById('security-health-status');
        if (secStatusEl) {
            if (s.detectedAttacks > 160) {
                secStatusEl.textContent = 'HIGH ALERT';
                secStatusEl.className = 'badge-status badge-danger';
            } else if (s.detectedAttacks > 100) {
                secStatusEl.textContent = 'ELEVATED MONITORING';
                secStatusEl.className = 'badge-status badge-suspicious';
            } else {
                secStatusEl.textContent = 'OPTIMAL / NORMAL';
                secStatusEl.className = 'badge-status badge-safe';
            }
        }
    },

    // Initialize the 5 required Chart.js charts
    initCharts: function() {
        if (!window.Chart) return;

        // Common Chart.js Light Theme Defaults
        Chart.defaults.font.family = "'Inter', sans-serif";
        Chart.defaults.color = '#64748B';
        Chart.defaults.borderColor = '#F1F5F9';

        // 1. Successful vs Failed Login Attempts (Stacked/Area Line Chart)
        const ctxSuccessFailed = document.getElementById('chartSuccessVsFailed');
        if (ctxSuccessFailed) {
            if (AASS_Dashboard.charts.successVsFailed) AASS_Dashboard.charts.successVsFailed.destroy();
            AASS_Dashboard.charts.successVsFailed = new Chart(ctxSuccessFailed, {
                type: 'line',
                data: {
                    labels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
                    datasets: [
                        {
                            label: 'Successful Logins',
                            data: [3800, 4200, 4100, 4650, 4400, 2700, 2776],
                            borderColor: '#2563EB',
                            backgroundColor: 'rgba(37, 99, 235, 0.08)',
                            fill: true,
                            tension: 0.35,
                            borderWidth: 2.5,
                            pointBackgroundColor: '#2563EB',
                            pointRadius: 3
                        },
                        {
                            label: 'Failed Attempts',
                            data: [210, 310, 190, 480, 240, 180, 214],
                            borderColor: '#DC2626',
                            backgroundColor: 'rgba(220, 38, 38, 0.06)',
                            fill: true,
                            tension: 0.35,
                            borderWidth: 2.5,
                            pointBackgroundColor: '#DC2626',
                            pointRadius: 3
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { position: 'top', labels: { boxWidth: 12, usePointStyle: true } }
                    },
                    scales: {
                        y: { grid: { color: '#F1F5F9' }, beginAtZero: true },
                        x: { grid: { display: false } }
                    }
                }
            });
        }

        // 2. Brute-Force Attacks Over Time (Bar / Trend Chart)
        const ctxAttacks = document.getElementById('chartAttacksOverTime');
        if (ctxAttacks) {
            if (AASS_Dashboard.charts.attacksOverTime) AASS_Dashboard.charts.attacksOverTime.destroy();
            AASS_Dashboard.charts.attacksOverTime = new Chart(ctxAttacks, {
                type: 'bar',
                data: {
                    labels: ['00:00', '03:00', '06:00', '09:00', '12:00', '15:00', '18:00', '21:00'],
                    datasets: [{
                        label: 'Detected Brute-Force Attacks',
                        data: [14, 8, 5, 22, 38, 29, 18, 8],
                        backgroundColor: '#7C3AED',
                        borderRadius: 6,
                        hoverBackgroundColor: '#6D28D9'
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { display: false }
                    },
                    scales: {
                        y: { grid: { color: '#F1F5F9' }, beginAtZero: true },
                        x: { grid: { display: false } }
                    }
                }
            });
        }

        // 3. Login Activity by Hour (24-Hour Distribution)
        const ctxHourly = document.getElementById('chartHourlyActivity');
        if (ctxHourly) {
            if (AASS_Dashboard.charts.hourlyActivity) AASS_Dashboard.charts.hourlyActivity.destroy();
            AASS_Dashboard.charts.hourlyActivity = new Chart(ctxHourly, {
                type: 'line',
                data: {
                    labels: ['12A', '2A', '4A', '6A', '8A', '10A', '12P', '2P', '4P', '6P', '8P', '10P'],
                    datasets: [{
                        label: 'Active Login Traffic',
                        data: [42, 18, 12, 65, 340, 680, 520, 610, 480, 310, 180, 85],
                        borderColor: '#16A34A',
                        backgroundColor: 'rgba(22, 163, 74, 0.08)',
                        tension: 0.35,
                        fill: true,
                        pointRadius: 2
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { display: false } },
                    scales: {
                        y: { grid: { color: '#F1F5F9' }, beginAtZero: true },
                        x: { grid: { display: false } }
                    }
                }
            });
        }

        // 4. Top Suspicious IP Addresses (Horizontal Bar Chart)
        const ctxIps = document.getElementById('chartTopSuspiciousIps');
        if (ctxIps) {
            if (AASS_Dashboard.charts.suspiciousIps) AASS_Dashboard.charts.suspiciousIps.destroy();
            AASS_Dashboard.charts.suspiciousIps = new Chart(ctxIps, {
                type: 'bar',
                indexAxis: 'y',
                data: {
                    labels: ['45.154.255.89', '185.220.101.5', '194.26.29.112', '91.240.118.234', '109.205.213.6'],
                    datasets: [{
                        label: 'Failed Attack Probes',
                        data: [48, 34, 26, 64, 12],
                        backgroundColor: ['#DC2626', '#EA580C', '#F59E0B', '#DC2626', '#EAB308'],
                        borderRadius: 6
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { display: false } },
                    scales: {
                        x: { grid: { color: '#F1F5F9' }, beginAtZero: true },
                        y: { grid: { display: false } }
                    }
                }
            });
        }

        // 5. Security Threat Distribution (Doughnut Chart)
        const ctxThreat = document.getElementById('chartThreatDistribution');
        if (ctxThreat) {
            if (AASS_Dashboard.charts.threatDistribution) AASS_Dashboard.charts.threatDistribution.destroy();
            AASS_Dashboard.charts.threatDistribution = new Chart(ctxThreat, {
                type: 'doughnut',
                data: {
                    labels: ['Dictionary Attacks', 'Credential Stuffing', 'Distributed Botnet', 'Slow Brute-Force', 'Normal Traffic'],
                    datasets: [{
                        data: [45, 28, 20, 15, 82],
                        backgroundColor: ['#DC2626', '#7C3AED', '#F59E0B', '#2563EB', '#16A34A'],
                        borderWidth: 2,
                        borderColor: '#FFFFFF'
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    cutout: '72%',
                    plugins: {
                        legend: { position: 'bottom', labels: { boxWidth: 12, usePointStyle: true, font: { size: 11 } } }
                    }
                }
            });
        }
    },

    loadLiveCharts: async function() {
        if (!AASS.isLiveBackend) return;
        try {
            const res = await fetch(`${AASS.apiBase}/dashboard/charts`);
            if (!res.ok) return;
            const data = await res.json();

            if (data.successVsFailed && AASS_Dashboard.charts.successVsFailed) {
                AASS_Dashboard.charts.successVsFailed.data.labels = data.successVsFailed.labels;
                AASS_Dashboard.charts.successVsFailed.data.datasets[0].data = data.successVsFailed.success;
                AASS_Dashboard.charts.successVsFailed.data.datasets[1].data = data.successVsFailed.failed;
                AASS_Dashboard.charts.successVsFailed.update('none');
            }
            if (data.attacksTimeline && AASS_Dashboard.charts.attacksOverTime) {
                AASS_Dashboard.charts.attacksOverTime.data.labels = data.attacksTimeline.labels;
                AASS_Dashboard.charts.attacksOverTime.data.datasets[0].data = data.attacksTimeline.attacks;
                AASS_Dashboard.charts.attacksOverTime.update('none');
            }
            if (data.hourlyActivity && AASS_Dashboard.charts.hourlyActivity) {
                AASS_Dashboard.charts.hourlyActivity.data.labels = data.hourlyActivity.labels;
                AASS_Dashboard.charts.hourlyActivity.data.datasets[0].data = data.hourlyActivity.traffic;
                AASS_Dashboard.charts.hourlyActivity.update('none');
            }
            if (data.topSuspiciousIps && AASS_Dashboard.charts.topSuspiciousIps) {
                AASS_Dashboard.charts.topSuspiciousIps.data.labels = data.topSuspiciousIps.labels;
                AASS_Dashboard.charts.topSuspiciousIps.data.datasets[0].data = data.topSuspiciousIps.probes;
                AASS_Dashboard.charts.topSuspiciousIps.update('none');
            }
            if (data.threatDistribution && AASS_Dashboard.charts.threatDistribution) {
                AASS_Dashboard.charts.threatDistribution.data.labels = data.threatDistribution.labels;
                AASS_Dashboard.charts.threatDistribution.data.datasets[0].data = data.threatDistribution.data;
                AASS_Dashboard.charts.threatDistribution.update('none');
            }
        } catch (e) {
            console.debug('Dashboard live charts synced.');
        }
    },

    updateCharts: function() {
        if (AASS_Dashboard.charts.successVsFailed) {
            const chart = AASS_Dashboard.charts.successVsFailed;
            chart.data.datasets[1].data[6] = AASS.data.stats.failedLogins % 500;
            chart.update('none');
        }
    },

    // Render Recent Login Activity Table
    renderRecentActivity: async function() {
        const tbody = document.getElementById('recent-activity-tbody');
        if (!tbody) return;

        if (AASS.isLiveBackend) {
            try {
                const res = await fetch(`${AASS.apiBase}/dashboard/activity`);
                if (res.ok) {
                    const data = await res.json();
                    if (data.activity && data.activity.length > 0) {
                        AASS.data.recentActivity = data.activity;
                    }
                }
            } catch (e) {}
        }

        tbody.innerHTML = '';
        const items = AASS.data.recentActivity.slice(0, 6);

        items.forEach(item => {
            let badgeClass = 'badge-safe';
            let badgeText = 'Success';
            if (item.status === 'FAILED') { badgeClass = 'badge-danger'; badgeText = 'Failed'; }
            if (item.status === 'CAPTCHA_TRIGGERED') { badgeClass = 'badge-suspicious'; badgeText = 'CAPTCHA'; }
            if (item.status === 'ACCOUNT_LOCKED') { badgeClass = 'badge-blocked'; badgeText = 'Locked'; }
            if (item.status === 'BLOCKED' || item.status === 'IP_BLOCKED') { badgeClass = 'badge-blocked'; badgeText = 'IP Blocked'; }

            let riskColor = item.risk > 70 ? 'var(--danger-red)' : (item.risk > 40 ? 'var(--warning-orange)' : 'var(--success-green)');

            const row = document.createElement('tr');
            row.innerHTML = `
                <td>
                    <div class="d-flex align-items-center gap-2">
                        <div class="user-avatar-mini" style="width:30px; height:30px; font-size:0.75rem;">
                            ${item.username.substring(0, 2).toUpperCase()}
                        </div>
                        <div>
                            <span class="font-semibold text-dark">${item.username}</span>
                        </div>
                    </div>
                </td>
                <td><code class="text-xs bg-slate-100 px-2 py-1 rounded" style="background:#F1F5F9; color:#0F172A;">${item.ip}</code></td>
                <td><span class="badge-status ${badgeClass}">${badgeText}</span></td>
                <td>
                    <div class="d-flex align-items-center gap-2">
                        <div class="risk-meter" style="width: 50px;">
                            <div class="risk-meter-fill" style="width: ${item.risk}%; background: ${riskColor};"></div>
                        </div>
                        <span class="text-xs font-semibold" style="color: ${riskColor};">${item.risk}%</span>
                    </div>
                </td>
                <td><span class="text-xs text-secondary">${item.time}</span></td>
            `;
            tbody.appendChild(row);
        });
    },

    // Render Recent Security Alerts Feed
    renderRecentAlerts: async function() {
        const container = document.getElementById('recent-alerts-container');
        if (!container) return;

        if (AASS.isLiveBackend) {
            try {
                const res = await fetch(`${AASS.apiBase}/dashboard/alerts`);
                if (res.ok) {
                    const data = await res.json();
                    if (data.alerts && data.alerts.length > 0) {
                        AASS.data.alerts = data.alerts;
                    }
                }
            } catch (e) {}
        }

        container.innerHTML = '';
        const alerts = AASS.data.alerts.slice(0, 4);

        alerts.forEach(alert => {
            let badgeClass = 'badge-danger';
            if (alert.risk === 'WARNING') badgeClass = 'badge-suspicious';
            if (alert.risk === 'INFO') badgeClass = 'badge-info';

            const item = document.createElement('div');
            item.className = 'd-flex align-items-start gap-3 p-3 rounded-xl mb-2';
            item.style.background = '#F8FAFC';
            item.style.border = '1px solid #E2E8F0';
            item.innerHTML = `
                <div style="margin-top: 3px;">
                    <span class="badge-status ${badgeClass}">${alert.risk}</span>
                </div>
                <div class="flex-grow-1">
                    <div class="d-flex justify-content-between align-items-center">
                        <strong class="text-sm font-semibold text-dark">${alert.type}</strong>
                        <span class="text-xs text-muted">${alert.timestamp}</span>
                    </div>
                    <div class="text-xs text-secondary mt-1">
                        Target: <span class="text-dark font-medium">${alert.username}</span> | IP: <code>${alert.ip}</code>
                    </div>
                    <div class="text-xs font-medium text-primary mt-1">
                        🛡️ Action: ${alert.action}
                    </div>
                </div>
            `;
            container.appendChild(item);
        });
    },

    // Render Suspicious & Blocked IPs mini-table
    renderSuspiciousIps: function() {
        const tbody = document.getElementById('suspicious-ips-tbody');
        if (!tbody) return;

        tbody.innerHTML = '';
        AASS.data.blockedIps.slice(0, 4).forEach(item => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td><code class="text-xs font-bold text-danger">${item.ip}</code></td>
                <td><span class="badge-status badge-blocked">Blocked</span></td>
                <td><span class="text-xs text-secondary">${item.attempts} attempts</span></td>
                <td>
                    <button class="btn-secondary-custom btn-sm-custom" onclick="AASS_Dashboard.unblockIp('${item.ip}')">
                        Unblock
                    </button>
                </td>
            `;
            tbody.appendChild(row);
        });
    },

    unblockIp: function(ip) {
        AASS.data.blockedIps = AASS.data.blockedIps.filter(item => item.ip !== ip);
        AASS.data.stats.blockedIps = Math.max(0, AASS.data.stats.blockedIps - 1);
        AASS.showToast(`IP address ${ip} has been removed from the blocklist.`, 'success', 'IP Unblocked');
        AASS_Dashboard.renderStats();
        AASS_Dashboard.renderSuspiciousIps();
    }
};

document.addEventListener('DOMContentLoaded', () => {
    AASS_Dashboard.init();
});

