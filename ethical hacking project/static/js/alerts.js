/**
 * Adaptive Authentication Security System (AASS)
 * Security Alerts Controller
 */

window.AASS_Alerts = {
    currentTab: 'ALL',
    searchTerm: '',

    init: function () {
        AASS_Alerts.renderAlerts();
        AASS_Alerts.bindControls();
    },

    bindControls: function () {
        const tabBtns = document.querySelectorAll('[data-alert-tab]');
        tabBtns.forEach(btn => {
            btn.addEventListener('click', () => {
                tabBtns.forEach(b => {
                    b.classList.remove('btn-primary-custom', 'active');
                    b.classList.add('btn-secondary-custom');
                });
                btn.classList.add('btn-primary-custom', 'active');
                btn.classList.remove('btn-secondary-custom');

                AASS_Alerts.currentTab = btn.getAttribute('data-alert-tab');
                AASS_Alerts.renderAlerts();
            });
        });

        const searchInput = document.getElementById('alerts-search-input');
        if (searchInput) {
            searchInput.addEventListener('input', (e) => {
                AASS_Alerts.searchTerm = e.target.value.toLowerCase().trim();
                AASS_Alerts.renderAlerts();
            });
        }
    },

    renderAlerts: async function () {
        const container = document.getElementById('alerts-list-container');
        if (!container) return;

        if (AASS.isLiveBackend) {
            try {
                const res = await fetch(`${AASS.apiBase}/alerts?severity=${AASS_Alerts.currentTab}&search=${encodeURIComponent(AASS_Alerts.searchTerm)}`);
                if (res.ok) {
                    const data = await res.json();
                    if (data.alerts) AASS.data.alerts = data.alerts;
                }
            } catch (e) { }
        }

        let filtered = AASS.data.alerts.filter(item => {
            const matchesTab = AASS_Alerts.currentTab === 'ALL' || item.risk === AASS_Alerts.currentTab;
            const matchesSearch = item.type.toLowerCase().includes(AASS_Alerts.searchTerm) ||
                item.username.toLowerCase().includes(AASS_Alerts.searchTerm) ||
                item.ip.toLowerCase().includes(AASS_Alerts.searchTerm) ||
                item.id.toLowerCase().includes(AASS_Alerts.searchTerm);
            return matchesTab && matchesSearch;
        });

        container.innerHTML = '';
        if (filtered.length === 0) {
            container.innerHTML = `
                <div class="card-custom p-5 text-center text-muted">
                    <i data-lucide="shield-check" style="width:48px; height:48px; color:var(--success-green); margin-bottom:12px;"></i>
                    <h5 class="text-dark font-semibold">No Security Alerts Found</h5>
                    <p class="text-xs mb-0">No active alerts matched the filter criteria.</p>
                </div>
            `;
            AASS.initLucide();
            return;
        }

        filtered.forEach(alert => {
            let badgeClass = 'badge-danger';
            let borderAccent = '4px solid var(--danger-red)';
            if (alert.risk === 'WARNING') {
                badgeClass = 'badge-suspicious';
                borderAccent = '4px solid var(--warning-orange)';
            }
            if (alert.risk === 'INFO') {
                badgeClass = 'badge-info';
                borderAccent = '4px solid var(--primary-blue)';
            }

            const card = document.createElement('div');
            card.className = 'card-custom p-4 mb-3 animate-fade-in';
            card.style.borderLeft = borderAccent;

            card.innerHTML = `
                <div class="d-flex justify-content-between align-items-start mb-2 flex-wrap gap-2">
                    <div class="d-flex align-items-center gap-2">
                        <span class="badge-status ${badgeClass}">${alert.risk}</span>
                        <code class="text-xs font-mono bg-slate-100 px-2 py-1 rounded text-dark font-semibold">${alert.id}</code>
                        <h6 class="font-bold text-dark mb-0">${alert.type}</h6>
                    </div>
                    <span class="text-xs text-muted font-medium">${alert.timestamp}</span>
                </div>
                <div class="row g-2 my-2 text-xs text-secondary">
                    <div class="col-sm-3">
                        <span class="text-muted d-block">Target Account</span>
                        <strong class="text-dark">${alert.username}</strong>
                    </div>
                    <div class="col-sm-3">
                        <span class="text-muted d-block">Attacker IP</span>
                        <code class="text-dark">${alert.ip}</code>
                    </div>
                    <div class="col-sm-3">
                        <span class="text-muted d-block">Action Taken</span>
                        <span class="text-primary font-medium">${alert.action}</span>
                    </div>
                    <div class="col-sm-3">
                        <span class="text-muted d-block">Current Status</span>
                        <span class="badge-status ${alert.status === 'Resolved' ? 'badge-safe' : 'badge-suspicious'}">${alert.status}</span>
                    </div>
                </div>
                <div class="d-flex justify-content-end gap-2 mt-3 pt-2 border-top">
                    ${alert.status !== 'Resolved' ? `
                        <button class="btn-primary-custom btn-sm-custom text-xs" onclick="AASS_Alerts.resolveAlert('${alert.id}')">
                            <i data-lucide="check" style="width:14px; height:14px;"></i> Mark as Resolved
                        </button>
                    ` : ''}
                    <button class="btn-secondary-custom btn-sm-custom text-xs" onclick="AASS_Alerts.viewForensics('${alert.ip}')">
                        <i data-lucide="search" style="width:14px; height:14px;"></i> Investigate IP
                    </button>
                    <button class="btn-secondary-custom btn-sm-custom text-xs" onclick="AASS_Alerts.dismissAlert('${alert.id}')">
                        <i data-lucide="trash-2" style="width:14px; height:14px;"></i> Dismiss
                    </button>
                </div>
            `;
            container.appendChild(card);
        });

        AASS.initLucide();
    },

    resolveAlert: async function (alertId) {
        if (AASS.isLiveBackend) {
            try {
                await fetch(`${AASS.apiBase}/alerts/${alertId}/resolve`, { method: 'POST' });
            } catch (e) { }
        }
        const item = AASS.data.alerts.find(a => a.id === alertId);
        if (item) {
            item.status = 'Resolved';
            AASS.showToast(`Alert ${alertId} resolved successfully.`, 'success');
            AASS_Alerts.renderAlerts();
        }
    },

    dismissAlert: async function (alertId) {
        if (AASS.isLiveBackend) {
            try {
                await fetch(`${AASS.apiBase}/alerts/${alertId}/dismiss`, { method: 'POST' });
            } catch (e) { }
        }
        AASS.data.alerts = AASS.data.alerts.filter(a => a.id !== alertId);
        AASS.showToast(`Alert ${alertId} dismissed.`, 'info');
        AASS_Alerts.renderAlerts();
    },

    viewForensics: function (ip) {
        window.location.href = `ip_monitoring.html?search=${encodeURIComponent(ip)}`;
    }
};

document.addEventListener('DOMContentLoaded', () => {
    AASS_Alerts.init();
});

