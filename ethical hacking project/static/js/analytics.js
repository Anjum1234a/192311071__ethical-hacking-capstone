/**
 * Adaptive Authentication Security System (AASS)
 * Security Analytics Controller & Forensic Visualizations
 */

window.AASS_Analytics = {
    charts: {},
    timeRange: '7d',

    init: function() {
        AASS_Analytics.initCharts();
        AASS_Analytics.renderTargetedAccounts();
        AASS_Analytics.renderAttackerIps();
        AASS_Analytics.bindFilters();
    },

    bindFilters: function() {
        const filterBtns = document.querySelectorAll('[data-timerange]');
        filterBtns.forEach(btn => {
            btn.addEventListener('click', (e) => {
                filterBtns.forEach(b => b.classList.remove('active', 'btn-primary-custom'));
                filterBtns.forEach(b => b.classList.add('btn-secondary-custom'));
                
                btn.classList.add('active', 'btn-primary-custom');
                btn.classList.remove('btn-secondary-custom');

                AASS_Analytics.timeRange = btn.getAttribute('data-timerange');
                AASS.showToast(`Analytics filtered by range: ${AASS_Analytics.timeRange.toUpperCase()}`, 'info');
                AASS_Analytics.updateAnalyticsData();
            });
        });

        const exportBtn = document.getElementById('btn-export-analytics');
        if (exportBtn) {
            exportBtn.addEventListener('click', AASS_Analytics.exportReport);
        }
    },

    initCharts: function() {
        if (!window.Chart) return;

        // 1. Daily & Weekly Attack Trends Chart
        const ctxTrends = document.getElementById('chartAttackTrends');
        if (ctxTrends) {
            AASS_Analytics.charts.trends = new Chart(ctxTrends, {
                type: 'line',
                data: {
                    labels: ['Day 1', 'Day 2', 'Day 3', 'Day 4', 'Day 5', 'Day 6', 'Day 7'],
                    datasets: [
                        {
                            label: 'Brute-Force Bursts',
                            data: [18, 25, 42, 31, 64, 48, 22],
                            borderColor: '#DC2626',
                            backgroundColor: 'rgba(220, 38, 38, 0.1)',
                            fill: true,
                            tension: 0.35,
                            borderWidth: 2
                        },
                        {
                            label: 'Adaptive Mitigations (CAPTCHA + Lockouts)',
                            data: [15, 23, 39, 29, 61, 46, 21],
                            borderColor: '#7C3AED',
                            backgroundColor: 'transparent',
                            borderDash: [5, 5],
                            borderWidth: 2
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { position: 'top' } },
                    scales: {
                        y: { grid: { color: '#F1F5F9' }, beginAtZero: true },
                        x: { grid: { display: false } }
                    }
                }
            });
        }

        // 2. Security Risk Score Distribution (Histogram)
        const ctxRiskDist = document.getElementById('chartRiskDistribution');
        if (ctxRiskDist) {
            AASS_Analytics.charts.riskDist = new Chart(ctxRiskDist, {
                type: 'bar',
                data: {
                    labels: ['0-20% (Safe)', '21-40% (Low)', '41-60% (Medium)', '61-80% (High)', '81-100% (Critical)'],
                    datasets: [{
                        label: 'Traffic Volume',
                        data: [18500, 4200, 1100, 650, 420],
                        backgroundColor: ['#16A34A', '#2563EB', '#F59E0B', '#EA580C', '#DC2626'],
                        borderRadius: 6
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { display: false } },
                    scales: {
                        y: { grid: { color: '#F1F5F9' } },
                        x: { grid: { display: false } }
                    }
                }
            });
        }

        // 3. Attack Method Breakdown (Doughnut)
        const ctxMethod = document.getElementById('chartMethodBreakdown');
        if (ctxMethod) {
            AASS_Analytics.charts.method = new Chart(ctxMethod, {
                type: 'doughnut',
                data: {
                    labels: ['Dictionary Attack', 'Single-IP Brute Force', 'Distributed Stuffing', 'Password Spraying', 'Token Replay'],
                    datasets: [{
                        data: [42, 28, 18, 9, 3],
                        backgroundColor: ['#DC2626', '#EA580C', '#7C3AED', '#F59E0B', '#2563EB']
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    cutout: '70%',
                    plugins: { legend: { position: 'bottom' } }
                }
            });
        }
    },

    updateAnalyticsData: async function() {
        if (!AASS_Analytics.charts.trends) return;

        if (AASS.isLiveBackend) {
            try {
                const res = await fetch(`${AASS.apiBase}/analytics/trends?range=${AASS_Analytics.timeRange}`);
                if (res.ok) {
                    const data = await res.json();
                    AASS_Analytics.charts.trends.data.labels = data.labels;
                    AASS_Analytics.charts.trends.data.datasets[0].data = data.attacks;
                    AASS_Analytics.charts.trends.data.datasets[1].data = data.mitigations;
                    AASS_Analytics.charts.trends.update();
                    return;
                }
            } catch (e) {}
        }

        const multiplier = AASS_Analytics.timeRange === 'today' ? 0.3 : (AASS_Analytics.timeRange === '30d' ? 3.5 : 1.0);
        
        AASS_Analytics.charts.trends.data.datasets[0].data = [18, 25, 42, 31, 64, 48, 22].map(v => Math.round(v * multiplier));
        AASS_Analytics.charts.trends.data.datasets[1].data = [15, 23, 39, 29, 61, 46, 21].map(v => Math.round(v * multiplier));
        AASS_Analytics.charts.trends.update();
    },

    renderTargetedAccounts: async function() {
        const tbody = document.getElementById('targeted-accounts-tbody');
        if (!tbody) return;

        let targets = [
            { username: 'admin', attempts: 384, attacks: 24, status: 'Active (Hardened)', lastTargeted: '8 mins ago' },
            { username: 'root', attempts: 256, attacks: 19, status: 'Disabled (Honeypot)', lastTargeted: '19 mins ago' },
            { username: 'finance_mgr', attempts: 142, attacks: 11, status: 'Locked (Auto-Cooldown)', lastTargeted: '32 mins ago' },
            { username: 'dev_ops', attempts: 89, attacks: 7, status: 'Active (2FA Enforced)', lastTargeted: '41 mins ago' },
            { username: 'support', attempts: 64, attacks: 4, status: 'Active (Safe)', lastTargeted: '2 hours ago' }
        ];

        if (AASS.isLiveBackend) {
            try {
                const res = await fetch(`${AASS.apiBase}/analytics/targeted-accounts`);
                if (res.ok) {
                    const data = await res.json();
                    if (data.targets) targets = data.targets;
                }
            } catch (e) {}
        }

        tbody.innerHTML = '';
        targets.forEach(t => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td><strong class="text-dark">${t.username}</strong></td>
                <td><span class="font-mono text-xs">${t.attempts}</span></td>
                <td><span class="badge-status badge-danger">${t.attacks} Attacks</span></td>
                <td><span class="text-xs ${t.status.includes('Locked') ? 'text-danger font-semibold' : 'text-secondary'}">${t.status}</span></td>
                <td><span class="text-xs text-muted">${t.lastTargeted}</span></td>
            `;
            tbody.appendChild(row);
        });
    },

    renderAttackerIps: async function() {
        const tbody = document.getElementById('attacker-ips-tbody');
        if (!tbody) return;

        let ips = [
            { ip: '45.154.255.89', country: 'RU / St. Petersburg', attempts: 312, method: 'Hydra Dictionary', risk: 99 },
            { ip: '185.220.101.5', country: 'DE / Tor Node', attempts: 245, method: 'Credential Stuffing', risk: 94 },
            { ip: '194.26.29.112', country: 'NL / Amsterdam', attempts: 189, method: 'High-speed Spraying', risk: 90 },
            { ip: '91.240.118.234', country: 'UA / Kyiv', attempts: 154, method: 'Automated Botnet', risk: 88 },
            { ip: '109.205.213.6', country: 'FR / Paris', attempts: 96, method: 'Python-Requests Probe', risk: 78 }
        ];

        if (AASS.isLiveBackend) {
            try {
                const res = await fetch(`${AASS.apiBase}/analytics/attacker-ips`);
                if (res.ok) {
                    const data = await res.json();
                    if (data.attackerIps) ips = data.attackerIps;
                }
            } catch (e) {}
        }

        tbody.innerHTML = '';
        ips.forEach(i => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td><code class="text-xs font-bold text-dark">${i.ip}</code></td>
                <td><span class="text-xs text-secondary">${i.country}</span></td>
                <td><span class="font-mono text-xs">${i.attempts}</span></td>
                <td><span class="badge-status badge-purple">${i.method}</span></td>
                <td><span class="badge-status badge-danger">${i.risk}%</span></td>
            `;
            tbody.appendChild(row);
        });
    },

    exportReport: function() {
        if (AASS.isLiveBackend) {
            window.location.href = `${AASS.apiBase}/analytics/export?format=json`;
            AASS.showToast('Security forensics report downloaded from live backend.', 'success');
            return;
        }

        const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(AASS.data, null, 2));
        const downloadAnchor = document.createElement('a');
        downloadAnchor.setAttribute("href", dataStr);
        downloadAnchor.setAttribute("download", `aass_security_forensic_report_${Date.now()}.json`);
        document.body.appendChild(downloadAnchor);
        downloadAnchor.click();
        downloadAnchor.remove();
        AASS.showToast('Security forensics report downloaded successfully.', 'success');
    }
};

document.addEventListener('DOMContentLoaded', () => {
    AASS_Analytics.init();
});

