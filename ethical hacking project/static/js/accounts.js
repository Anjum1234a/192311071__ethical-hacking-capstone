/**
 * Adaptive Authentication Security System (AASS)
 * User Account & Lockout Management Controller
 */

window.AASS_Accounts = {
    users: [
        { id: 1, name: 'System Administrator', username: 'admin', email: 'admin@sentinel.ai', role: 'Administrator', status: 'Active', failedAttempts: 0, lastLogin: '2 mins ago' },
        { id: 2, name: 'Security Analyst', username: 'sec_analyst', email: 'analyst@sentinel.ai', role: 'Security Analyst', status: 'Active', failedAttempts: 0, lastLogin: '8 mins ago' },
        { id: 3, name: 'Threat Hunter', username: 'threat_hunter', email: 'hunter@sentinel.ai', role: 'Threat Hunter', status: 'Active', failedAttempts: 0, lastLogin: '14 mins ago' },
        { id: 4, name: 'Finance Controller', username: 'finance_mgr', email: 'finance@sentinel.ai', role: 'Standard User', status: 'Locked', failedAttempts: 5, lastLogin: '32 mins ago' },
        { id: 5, name: 'Alex Turner', username: 'alex_turner', email: 'alex.t@sentinel.ai', role: 'Standard User', status: 'Locked', failedAttempts: 6, lastLogin: '1 hour ago' },
        { id: 6, name: 'DevOps Lead', username: 'dev_ops', email: 'devops@sentinel.ai', role: 'Security Analyst', status: 'Active', failedAttempts: 1, lastLogin: '41 mins ago' }
    ],

    init: function() {
        AASS_Accounts.renderTable();
        AASS_Accounts.bindControls();
    },

    bindControls: function() {
        const searchInput = document.getElementById('account-search-input');
        if (searchInput) {
            searchInput.addEventListener('input', (e) => {
                const term = e.target.value.toLowerCase();
                AASS_Accounts.renderTable(term);
            });
        }

        const createForm = document.getElementById('new-user-form');
        if (createForm) {
            createForm.addEventListener('submit', async (e) => {
                e.preventDefault();
                const name = document.getElementById('new-user-name').value;
                const username = document.getElementById('new-user-username').value;
                const email = document.getElementById('new-user-email').value;
                const role = document.getElementById('new-user-role').value;

                if (AASS.isLiveBackend) {
                    try {
                        const res = await fetch(`${AASS.apiBase}/accounts/create`, {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ name, username, email, role })
                        });
                        const result = await res.json();
                        if (res.ok) {
                            AASS.showToast(result.message, 'success');
                            const modal = bootstrap.Modal.getInstance(document.getElementById('newUserModal'));
                            if (modal) modal.hide();
                            createForm.reset();
                            AASS_Accounts.renderTable();
                            return;
                        } else {
                            AASS.showToast(result.message || 'Failed to create user', 'danger');
                            return;
                        }
                    } catch (e) {}
                }

                AASS_Accounts.users.push({
                    id: Date.now(),
                    name: name,
                    username: username,
                    email: email,
                    role: role,
                    status: 'Active',
                    failedAttempts: 0,
                    lastLogin: 'Never'
                });

                AASS.data.stats.totalUsers++;
                AASS.showToast(`User ${username} created successfully with active security profile.`, 'success');
                const modal = bootstrap.Modal.getInstance(document.getElementById('newUserModal'));
                if (modal) modal.hide();
                createForm.reset();
                AASS_Accounts.renderTable();
            });
        }
    },

    renderTable: async function(searchTerm = '') {
        const tbody = document.getElementById('accounts-table-tbody');
        if (!tbody) return;

        if (AASS.isLiveBackend) {
            try {
                const res = await fetch(`${AASS.apiBase}/accounts?search=${encodeURIComponent(searchTerm)}`);
                if (res.ok) {
                    const data = await res.json();
                    if (data.users) AASS_Accounts.users = data.users;
                }
            } catch (e) {}
        }

        let filtered = AASS_Accounts.users.filter(u => {
            return u.name.toLowerCase().includes(searchTerm) ||
                   u.username.toLowerCase().includes(searchTerm) ||
                   u.email.toLowerCase().includes(searchTerm);
        });

        tbody.innerHTML = '';
        filtered.forEach(user => {
            let badgeClass = user.status === 'Active' ? 'badge-safe' : 'badge-danger';
            let roleBadge = user.role.includes('Admin') ? 'badge-purple' : 'badge-info';

            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>
                    <div class="d-flex align-items-center gap-2">
                        <div class="user-avatar-mini" style="width:34px; height:34px;">
                            ${user.username.substring(0, 2).toUpperCase()}
                        </div>
                        <div>
                            <strong class="text-dark d-block text-sm">${user.name}</strong>
                            <span class="text-xs text-muted">@${user.username}</span>
                        </div>
                    </div>
                </td>
                <td><span class="text-xs text-secondary">${user.email}</span></td>
                <td><span class="badge-status ${roleBadge}">${user.role}</span></td>
                <td><span class="badge-status ${badgeClass}">${user.status}</span></td>
                <td><span class="font-mono text-xs ${user.failedAttempts > 0 ? 'text-danger font-bold' : ''}">${user.failedAttempts}</span></td>
                <td><span class="text-xs text-muted">${user.lastLogin}</span></td>
                <td>
                    <div class="d-flex gap-1">
                        ${user.status === 'Locked' ? `
                            <button class="btn-primary-custom btn-sm-custom text-xs" onclick="AASS_Accounts.unlockUser(${user.id})">
                                <i data-lucide="unlock" style="width:12px; height:12px;"></i> Unlock
                            </button>
                        ` : `
                            <button class="btn-secondary-custom btn-sm-custom text-xs" onclick="AASS_Accounts.lockUser(${user.id})">
                                Lock
                            </button>
                        `}
                        <button class="btn-icon btn-sm-custom" title="Reset Password" onclick="AASS_Accounts.resetPassword('${user.username}')">
                            <i data-lucide="key" style="width:13px; height:13px;"></i>
                        </button>
                    </div>
                </td>
            `;
            tbody.appendChild(tr);
        });

        AASS.initLucide();
    },

    unlockUser: async function(id) {
        if (AASS.isLiveBackend) {
            try {
                const res = await fetch(`${AASS.apiBase}/accounts/unlock`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ userId: id })
                });
                if (res.ok) {
                    const result = await res.json();
                    AASS.showToast(result.message, 'success', 'Account Unlocked');
                    AASS_Accounts.renderTable();
                    return;
                }
            } catch (e) {}
        }

        const user = AASS_Accounts.users.find(u => u.id === id);
        if (user) {
            user.status = 'Active';
            user.failedAttempts = 0;
            AASS.showToast(`Account [${user.username}] unlocked. Brute-force lockout counter cleared.`, 'success', 'Account Unlocked');
            AASS_Accounts.renderTable();
        }
    },

    lockUser: async function(id) {
        if (AASS.isLiveBackend) {
            try {
                const res = await fetch(`${AASS.apiBase}/accounts/lock`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ userId: id })
                });
                if (res.ok) {
                    const result = await res.json();
                    AASS.showToast(result.message, 'warning', 'Account Locked');
                    AASS_Accounts.renderTable();
                    return;
                }
            } catch (e) {}
        }

        const user = AASS_Accounts.users.find(u => u.id === id);
        if (user) {
            user.status = 'Locked';
            user.failedAttempts = AASS.settings.maxFailedAttempts;
            AASS.showToast(`Account [${user.username}] placed in defensive lockout.`, 'warning', 'Account Locked');
            AASS_Accounts.renderTable();
        }
    },

    resetPassword: async function(username) {
        if (AASS.isLiveBackend) {
            try {
                const res = await fetch(`${AASS.apiBase}/accounts/reset-password`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username: username })
                });
                if (res.ok) {
                    const result = await res.json();
                    AASS.showToast(result.message, 'info', 'Password Reset');
                    return;
                }
            } catch (e) {}
        }

        AASS.showToast(`Password reset link dispatched for @${username}. Hash will be regenerated.`, 'info');
    }
};

document.addEventListener('DOMContentLoaded', () => {
    AASS_Accounts.init();
});

