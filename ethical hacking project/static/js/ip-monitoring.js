/**
 * Adaptive Authentication Security System (AASS)
 * IP Address Monitoring Controller
 */

window.AASS_IpMonitoring = {
    searchTerm: '',
    statusFilter: 'all',
    currentPage: 1,
    pageSize: 8,

    init: function() {
        AASS_IpMonitoring.renderTable();
        AASS_IpMonitoring.bindControls();
    },

    bindControls: function() {
        const searchInput = document.getElementById('ip-search-input');
        if (searchInput) {
            searchInput.addEventListener('input', (e) => {
                AASS_IpMonitoring.searchTerm = e.target.value.toLowerCase().trim();
                AASS_IpMonitoring.currentPage = 1;
                AASS_IpMonitoring.renderTable();
            });
        }

        const filterSelect = document.getElementById('ip-filter-status');
        if (filterSelect) {
            filterSelect.addEventListener('change', (e) => {
                AASS_IpMonitoring.statusFilter = e.target.value;
                AASS_IpMonitoring.currentPage = 1;
                AASS_IpMonitoring.renderTable();
            });
        }

        const addIpBtn = document.getElementById('btn-add-manual-ip');
        if (addIpBtn) {
            addIpBtn.addEventListener('click', AASS_IpMonitoring.openManualBlockModal);
        }
    },

    renderTable: async function() {
        const tbody = document.getElementById('ip-table-tbody');
        if (!tbody) return;

        if (AASS.isLiveBackend) {
            try {
                const res = await fetch(`${AASS.apiBase}/ip-monitoring?search=${encodeURIComponent(AASS_IpMonitoring.searchTerm)}&status=${AASS_IpMonitoring.statusFilter}&page=${AASS_IpMonitoring.currentPage}`);
                if (res.ok) {
                    const data = await res.json();
                    if (data.items) {
                        AASS.data.ipDirectory = data.items;
                        tbody.innerHTML = '';
                        if (data.items.length === 0) {
                            tbody.innerHTML = `<tr><td colspan="8" class="text-center py-4 text-muted">No IP records found matching the current search criteria.</td></tr>`;
                            return;
                        }
                        data.items.forEach(row => {
                            let badgeClass = 'badge-safe';
                            let statusAction = '';
                            if (row.status === 'Suspicious') badgeClass = 'badge-suspicious';
                            if (row.status === 'Blocked') {
                                badgeClass = 'badge-blocked';
                                statusAction = `<button class="btn-secondary-custom btn-sm-custom text-xs" onclick="AASS_IpMonitoring.unblockIp('${row.ip}')">Unblock</button>`;
                            } else {
                                statusAction = `<button class="btn-danger-custom btn-sm-custom text-xs" onclick="AASS_IpMonitoring.blockIp('${row.ip}')">Block IP</button>`;
                            }

                            let riskColor = row.risk > 70 ? 'var(--danger-red)' : (row.risk > 40 ? 'var(--warning-orange)' : 'var(--success-green)');

                            const tr = document.createElement('tr');
                            tr.innerHTML = `
                                <td><code class="font-bold text-dark">${row.ip}</code></td>
                                <td><span class="font-mono">${row.total}</span></td>
                                <td><span class="font-mono text-danger font-semibold">${row.failed}</span></td>
                                <td><span class="font-mono text-success font-semibold">${row.success}</span></td>
                                <td>
                                    <div class="d-flex align-items-center gap-2">
                                        <div class="risk-meter" style="width: 50px;">
                                            <div class="risk-meter-fill" style="width: ${row.risk}%; background: ${riskColor};"></div>
                                        </div>
                                        <span class="text-xs font-semibold" style="color: ${riskColor};">${row.risk}%</span>
                                    </div>
                                </td>
                                <td><span class="badge-status ${badgeClass}">${row.status}</span></td>
                                <td><span class="text-xs text-muted">${row.lastActivity}</span></td>
                                <td>
                                    <div class="d-flex gap-1">
                                        ${statusAction}
                                        <button class="btn-icon btn-sm-custom" title="Audit Log" onclick="AASS_IpMonitoring.inspectIp('${row.ip}')">
                                            <i data-lucide="eye" style="width:14px; height:14px;"></i>
                                        </button>
                                    </div>
                                </td>
                            `;
                            tbody.appendChild(tr);
                        });
                        AASS.initLucide();
                        AASS_IpMonitoring.renderPagination(data.pages || 1);
                        return;
                    }
                }
            } catch (e) {}
        }

        let filtered = AASS.data.ipDirectory.filter(item => {
            const matchesSearch = item.ip.toLowerCase().includes(AASS_IpMonitoring.searchTerm);
            const matchesStatus = AASS_IpMonitoring.statusFilter === 'all' || item.status.toLowerCase() === AASS_IpMonitoring.statusFilter.toLowerCase();
            return matchesSearch && matchesStatus;
        });

        const totalItems = filtered.length;
        const totalPages = Math.max(1, Math.ceil(totalItems / AASS_IpMonitoring.pageSize));
        const start = (AASS_IpMonitoring.currentPage - 1) * AASS_IpMonitoring.pageSize;
        const paged = filtered.slice(start, start + AASS_IpMonitoring.pageSize);

        tbody.innerHTML = '';
        if (paged.length === 0) {
            tbody.innerHTML = `<tr><td colspan="8" class="text-center py-4 text-muted">No IP records found matching the current search criteria.</td></tr>`;
            return;
        }

        paged.forEach(row => {
            let badgeClass = 'badge-safe';
            let statusAction = '';
            if (row.status === 'Suspicious') badgeClass = 'badge-suspicious';
            if (row.status === 'Blocked') {
                badgeClass = 'badge-blocked';
                statusAction = `<button class="btn-secondary-custom btn-sm-custom text-xs" onclick="AASS_IpMonitoring.unblockIp('${row.ip}')">Unblock</button>`;
            } else {
                statusAction = `<button class="btn-danger-custom btn-sm-custom text-xs" onclick="AASS_IpMonitoring.blockIp('${row.ip}')">Block IP</button>`;
            }

            let riskColor = row.risk > 70 ? 'var(--danger-red)' : (row.risk > 40 ? 'var(--warning-orange)' : 'var(--success-green)');

            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td><code class="font-bold text-dark">${row.ip}</code></td>
                <td><span class="font-mono">${row.total}</span></td>
                <td><span class="font-mono text-danger font-semibold">${row.failed}</span></td>
                <td><span class="font-mono text-success font-semibold">${row.success}</span></td>
                <td>
                    <div class="d-flex align-items-center gap-2">
                        <div class="risk-meter" style="width: 50px;">
                            <div class="risk-meter-fill" style="width: ${row.risk}%; background: ${riskColor};"></div>
                        </div>
                        <span class="text-xs font-semibold" style="color: ${riskColor};">${row.risk}%</span>
                    </div>
                </td>
                <td><span class="badge-status ${badgeClass}">${row.status}</span></td>
                <td><span class="text-xs text-muted">${row.lastActivity}</span></td>
                <td>
                    <div class="d-flex gap-1">
                        ${statusAction}
                        <button class="btn-icon btn-sm-custom" title="Audit Log" onclick="AASS_IpMonitoring.inspectIp('${row.ip}')">
                            <i data-lucide="eye" style="width:14px; height:14px;"></i>
                        </button>
                    </div>
                </td>
            `;
            tbody.appendChild(tr);
        });

        AASS.initLucide();
        AASS_IpMonitoring.renderPagination(totalPages);
    },

    renderPagination: function(totalPages) {
        const pagEl = document.getElementById('ip-pagination');
        if (!pagEl) return;
        pagEl.innerHTML = `
            <div class="text-xs text-muted">Page ${AASS_IpMonitoring.currentPage} of ${totalPages}</div>
            <div class="d-flex gap-1">
                <button class="btn-secondary-custom btn-sm-custom" ${AASS_IpMonitoring.currentPage <= 1 ? 'disabled' : ''} onclick="AASS_IpMonitoring.changePage(-1)">Prev</button>
                <button class="btn-secondary-custom btn-sm-custom" ${AASS_IpMonitoring.currentPage >= totalPages ? 'disabled' : ''} onclick="AASS_IpMonitoring.changePage(1)">Next</button>
            </div>
        `;
    },

    changePage: function(delta) {
        AASS_IpMonitoring.currentPage += delta;
        AASS_IpMonitoring.renderTable();
    },

    blockIp: async function(ip) {
        if (AASS.isLiveBackend) {
            try {
                await fetch(`${AASS.apiBase}/ip-monitoring/block`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ ip: ip })
                });
            } catch (e) {}
        }
        const item = AASS.data.ipDirectory.find(i => i.ip === ip);
        if (item) {
            item.status = 'Blocked';
            item.risk = 98;
        }
        if (!AASS.data.blockedIps.some(i => i.ip === ip)) {
            AASS.data.blockedIps.unshift({
                ip: ip,
                reason: 'Administrator Manual Block Enforcement',
                attempts: item ? item.total : 1,
                failed: item ? item.failed : 1,
                risk: 98,
                status: 'Blocked',
                blockedAt: 'Just now',
                expiresAt: 'Manual Unblock'
            });
            AASS.data.stats.blockedIps++;
        }
        AASS.showToast(`IP address ${ip} has been blocked and quarantined.`, 'danger', 'IP Quarantined');
        AASS_IpMonitoring.renderTable();
    },

    unblockIp: async function(ip) {
        if (AASS.isLiveBackend) {
            try {
                await fetch(`${AASS.apiBase}/ip-monitoring/unblock`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ ip: ip })
                });
            } catch (e) {}
        }
        const item = AASS.data.ipDirectory.find(i => i.ip === ip);
        if (item) {
            item.status = 'Safe';
            item.risk = 15;
        }
        AASS.data.blockedIps = AASS.data.blockedIps.filter(i => i.ip !== ip);
        AASS.data.stats.blockedIps = Math.max(0, AASS.data.stats.blockedIps - 1);
        AASS.showToast(`IP address ${ip} unblocked and restored to safe whitelist.`, 'success', 'IP Restored');
        AASS_IpMonitoring.renderTable();
    },

    inspectIp: function(ip) {
        AASS.showToast(`Viewing forensic logs for IP: ${ip}`, 'info');
        window.location.href = `login_history.html?ip=${encodeURIComponent(ip)}`;
    },

    openManualBlockModal: function() {
        const ip = prompt("Enter IP Address to block immediately (e.g. 198.51.100.99):");
        if (ip && ip.trim()) {
            AASS.data.ipDirectory.unshift({
                ip: ip.trim(),
                total: 10,
                failed: 10,
                success: 0,
                risk: 99,
                status: 'Blocked',
                lastActivity: 'Just now'
            });
            AASS_IpMonitoring.blockIp(ip.trim());
        }
    }
};

document.addEventListener('DOMContentLoaded', () => {
    AASS_IpMonitoring.init();
});

