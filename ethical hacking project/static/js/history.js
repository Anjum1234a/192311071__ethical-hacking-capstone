/**
 * Adaptive Authentication Security System (AASS)
 * Login History & Audit Trail Controller
 */

window.AASS_History = {
    searchTerm: '',
    statusFilter: 'all',
    currentPage: 1,
    pageSize: 10,

    init: function() {
        // Check if query params have IP or username filter
        const params = new URLSearchParams(window.location.search);
        if (params.get('ip')) {
            AASS_History.searchTerm = params.get('ip');
            const searchInput = document.getElementById('history-search-input');
            if (searchInput) searchInput.value = AASS_History.searchTerm;
        }

        AASS_History.renderTable();
        AASS_History.bindControls();
    },

    bindControls: function() {
        const searchInput = document.getElementById('history-search-input');
        if (searchInput) {
            searchInput.addEventListener('input', (e) => {
                AASS_History.searchTerm = e.target.value.toLowerCase().trim();
                AASS_History.currentPage = 1;
                AASS_History.renderTable();
            });
        }

        const filterSelect = document.getElementById('history-filter-status');
        if (filterSelect) {
            filterSelect.addEventListener('change', (e) => {
                AASS_History.statusFilter = e.target.value;
                AASS_History.currentPage = 1;
                AASS_History.renderTable();
            });
        }

        const exportBtn = document.getElementById('btn-export-history');
        if (exportBtn) {
            exportBtn.addEventListener('click', AASS_History.exportCsv);
        }
    },

    renderTable: async function() {
        const tbody = document.getElementById('history-table-tbody');
        if (!tbody) return;

        if (AASS.isLiveBackend) {
            try {
                const res = await fetch(`${AASS.apiBase}/history?search=${encodeURIComponent(AASS_History.searchTerm)}&status=${AASS_History.statusFilter}&page=${AASS_History.currentPage}`);
                if (res.ok) {
                    const data = await res.json();
                    if (data.items) {
                        tbody.innerHTML = '';
                        if (data.items.length === 0) {
                            tbody.innerHTML = `<tr><td colspan="7" class="text-center py-4 text-muted">No audit logs found matching criteria.</td></tr>`;
                            return;
                        }
                        data.items.forEach(row => {
                            let badgeClass = 'badge-safe';
                            if (row.status === 'FAILED') badgeClass = 'badge-danger';
                            if (row.status === 'CAPTCHA_TRIGGERED') badgeClass = 'badge-suspicious';
                            if (row.status.includes('LOCKED') || row.status.includes('BLOCKED')) badgeClass = 'badge-blocked';

                            let riskColor = row.risk > 70 ? 'var(--danger-red)' : (row.risk > 40 ? 'var(--warning-orange)' : 'var(--success-green)');

                            const tr = document.createElement('tr');
                            tr.innerHTML = `
                                <td><span class="text-xs text-muted font-mono">${row.time}</span></td>
                                <td><strong class="text-dark">${row.username}</strong></td>
                                <td><code class="text-xs font-mono bg-slate-100 px-2 py-1 rounded text-dark">${row.ip}</code></td>
                                <td><span class="badge-status ${badgeClass}">${row.status}</span></td>
                                <td>
                                    <div class="d-flex align-items-center gap-2">
                                        <div class="risk-meter" style="width: 45px;">
                                            <div class="risk-meter-fill" style="width: ${row.risk}%; background: ${riskColor};"></div>
                                        </div>
                                        <span class="text-xs font-semibold" style="color: ${riskColor};">${row.risk}%</span>
                                    </div>
                                </td>
                                <td><span class="text-xs text-secondary text-truncate d-inline-block" style="max-width: 220px;" title="${row.userAgent}">${row.userAgent}</span></td>
                                <td><span class="badge-status badge-purple text-xs">Argon2 / Bcrypt</span></td>
                            `;
                            tbody.appendChild(tr);
                        });
                        AASS_History.renderPagination(data.pages || 1);
                        return;
                    }
                }
            } catch (e) {}
        }

        let filtered = AASS.data.recentActivity.filter(item => {
            const matchesSearch = item.username.toLowerCase().includes(AASS_History.searchTerm) ||
                                  item.ip.toLowerCase().includes(AASS_History.searchTerm) ||
                                  item.userAgent.toLowerCase().includes(AASS_History.searchTerm);
            const matchesStatus = AASS_History.statusFilter === 'all' || item.status.toLowerCase().includes(AASS_History.statusFilter.toLowerCase());
            return matchesSearch && matchesStatus;
        });

        const totalItems = filtered.length;
        const totalPages = Math.max(1, Math.ceil(totalItems / AASS_History.pageSize));
        const start = (AASS_History.currentPage - 1) * AASS_History.pageSize;
        const paged = filtered.slice(start, start + AASS_History.pageSize);

        tbody.innerHTML = '';
        if (paged.length === 0) {
            tbody.innerHTML = `<tr><td colspan="7" class="text-center py-4 text-muted">No audit logs found matching criteria.</td></tr>`;
            return;
        }

        paged.forEach(row => {
            let badgeClass = 'badge-safe';
            if (row.status === 'FAILED') badgeClass = 'badge-danger';
            if (row.status === 'CAPTCHA_TRIGGERED') badgeClass = 'badge-suspicious';
            if (row.status.includes('LOCKED') || row.status.includes('BLOCKED')) badgeClass = 'badge-blocked';

            let riskColor = row.risk > 70 ? 'var(--danger-red)' : (row.risk > 40 ? 'var(--warning-orange)' : 'var(--success-green)');

            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td><span class="text-xs text-muted font-mono">${row.time}</span></td>
                <td><strong class="text-dark">${row.username}</strong></td>
                <td><code class="text-xs font-mono bg-slate-100 px-2 py-1 rounded text-dark">${row.ip}</code></td>
                <td><span class="badge-status ${badgeClass}">${row.status}</span></td>
                <td>
                    <div class="d-flex align-items-center gap-2">
                        <div class="risk-meter" style="width: 45px;">
                            <div class="risk-meter-fill" style="width: ${row.risk}%; background: ${riskColor};"></div>
                        </div>
                        <span class="text-xs font-semibold" style="color: ${riskColor};">${row.risk}%</span>
                    </div>
                </td>
                <td><span class="text-xs text-secondary text-truncate d-inline-block" style="max-width: 220px;" title="${row.userAgent}">${row.userAgent}</span></td>
                <td><span class="badge-status badge-purple text-xs">Standard Password</span></td>
            `;
            tbody.appendChild(tr);
        });

        AASS_History.renderPagination(totalPages);
    },

    renderPagination: function(totalPages) {
        const pagEl = document.getElementById('history-pagination');
        if (!pagEl) return;
        pagEl.innerHTML = `
            <div class="text-xs text-muted">Page ${AASS_History.currentPage} of ${totalPages}</div>
            <div class="d-flex gap-1">
                <button class="btn-secondary-custom btn-sm-custom" ${AASS_History.currentPage <= 1 ? 'disabled' : ''} onclick="AASS_History.changePage(-1)">Prev</button>
                <button class="btn-secondary-custom btn-sm-custom" ${AASS_History.currentPage >= totalPages ? 'disabled' : ''} onclick="AASS_History.changePage(1)">Next</button>
            </div>
        `;
    },

    changePage: function(delta) {
        AASS_History.currentPage += delta;
        AASS_History.renderTable();
    },

    exportCsv: function() {
        if (AASS.isLiveBackend) {
            window.location.href = `${AASS.apiBase}/history/export`;
            AASS.showToast('Login audit trail exported from database.', 'success');
            return;
        }

        let csv = 'Timestamp,Username,IP Address,Status,Risk Score,User Agent\n';
        AASS.data.recentActivity.forEach(r => {
            csv += `"${r.time}","${r.username}","${r.ip}","${r.status}",${r.risk},"${r.userAgent.replace(/"/g, '""')}"\n`;
        });
        const blob = new Blob([csv], { type: 'text/csv' });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `aass_login_audit_trail_${Date.now()}.csv`;
        a.click();
        window.URL.revokeObjectURL(url);
        AASS.showToast('Login audit trail exported as CSV successfully.', 'success');
    }
};

document.addEventListener('DOMContentLoaded', () => {
    AASS_History.init();
});

