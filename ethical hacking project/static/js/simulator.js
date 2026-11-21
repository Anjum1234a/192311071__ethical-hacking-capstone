/**
 * Adaptive Authentication Security System (AASS)
 * Interactive Attack Simulation Engine for Testing & Final Year Project Demos
 */

window.AASS_Simulator = {
    isRunning: false,
    intervalId: null,
    attackCount: 0,
    targetUsername: 'admin',
    attackType: 'bruteforce',

    // Common brute-force password dictionary for realistic simulation
    dictionary: ['123456', 'password', 'admin123', 'welcome', 'qwerty', 'letmein', 'security2024', 'rootpass', 'supersecret'],
    attackerIps: ['45.154.255.89', '185.220.101.5', '194.26.29.112', '91.240.118.234', '109.205.213.6', '198.51.100.23'],

    // Single step simulated login attempt
    simulateSingleAttempt: function(isSuccess = false, username = 'admin', customIp = null) {
        const ip = customIp || AASS_Simulator.attackerIps[Math.floor(Math.random() * AASS_Simulator.attackerIps.length)];
        
        // Post directly to Python Adaptive Engine Backend if live
        if (AASS.isLiveBackend) {
            fetch(`${AASS.apiBase}/realtime/simulate`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    type: isSuccess ? 'success' : 'single_fail',
                    username: username,
                    ip: ip
                })
            }).catch(e => console.warn('Simulation backend sync failed'));
        }

        const attemptPassword = isSuccess ? 'ValidSecureP@ss123' : AASS_Simulator.dictionary[Math.floor(Math.random() * AASS_Simulator.dictionary.length)];
        
        let status = isSuccess ? 'SUCCESS' : 'FAILED';
        let riskScore = isSuccess ? Math.floor(Math.random() * 15) : Math.min(99, 30 + (AASS_Simulator.attackCount * 18));
        
        // Adaptive Security Logic evaluation
        let actionTaken = 'Logged';
        let alertGenerated = null;

        if (!isSuccess) {
            AASS_Simulator.attackCount++;
            
            // Check CAPTCHA threshold
            if (AASS_Simulator.attackCount >= AASS.settings.captchaThreshold && AASS_Simulator.attackCount < AASS.settings.maxFailedAttempts) {
                status = 'CAPTCHA_TRIGGERED';
                riskScore = Math.max(riskScore, 65);
                actionTaken = 'Enforced CAPTCHA Challenge';
                alertGenerated = {
                    id: 'ALT-' + Math.floor(1000 + Math.random() * 9000),
                    type: 'Suspicious Activity Detected',
                    ip: ip,
                    username: username,
                    risk: 'WARNING',
                    status: 'Challenged',
                    action: actionTaken,
                    timestamp: 'Just now'
                };
            }
            // Check Account Lockout threshold
            else if (AASS_Simulator.attackCount >= AASS.settings.maxFailedAttempts && AASS_Simulator.attackCount < AASS.settings.ipBlockThreshold) {
                status = 'ACCOUNT_LOCKED';
                riskScore = Math.max(riskScore, 88);
                actionTaken = `Account Locked for ${AASS.settings.lockoutMinutes}m`;
                alertGenerated = {
                    id: 'ALT-' + Math.floor(1000 + Math.random() * 9000),
                    type: 'Account Lockout Triggered',
                    ip: ip,
                    username: username,
                    risk: 'CRITICAL',
                    status: 'Active Lock',
                    action: actionTaken,
                    timestamp: 'Just now'
                };
            }
            // Check IP Block threshold
            else if (AASS_Simulator.attackCount >= AASS.settings.ipBlockThreshold) {
                status = 'IP_BLOCKED';
                riskScore = 99;
                actionTaken = 'IP Permanently Isolated & Blocked';
                alertGenerated = {
                    id: 'ALT-' + Math.floor(1000 + Math.random() * 9000),
                    type: 'Brute-Force Attack Blocked',
                    ip: ip,
                    username: username,
                    risk: 'CRITICAL',
                    status: 'Blocked',
                    action: actionTaken,
                    timestamp: 'Just now'
                };

                // Add to blocked IP list if not present
                if (!AASS.data.blockedIps.some(item => item.ip === ip)) {
                    AASS.data.blockedIps.unshift({
                        ip: ip,
                        reason: 'Automated Real-Time Brute-Force Detection',
                        attempts: AASS_Simulator.attackCount,
                        failed: AASS_Simulator.attackCount,
                        risk: riskScore,
                        status: 'Blocked',
                        blockedAt: 'Just now',
                        expiresAt: 'In 60 mins'
                    });
                    AASS.data.stats.blockedIps++;
                }
            }
        } else {
            // Reset counter on genuine login
            AASS_Simulator.attackCount = 0;
        }

        // Record event in activity feed
        const activityItem = {
            id: Date.now(),
            username: username,
            ip: ip,
            status: status,
            risk: riskScore,
            time: 'Just now',
            location: 'Simulated Node / Test Harness',
            userAgent: isSuccess ? 'Chrome 122 / Win11' : 'Hydra/Kali-Linux (Brute-Force Tool)'
        };

        AASS.data.recentActivity.unshift(activityItem);
        if (AASS.data.recentActivity.length > 50) AASS.data.recentActivity.pop();

        // Update stats
        AASS.data.stats.totalLogins++;
        if (isSuccess) {
            AASS.data.stats.successLogins++;
        } else {
            AASS.data.stats.failedLogins++;
            if (status !== 'FAILED') AASS.data.stats.detectedAttacks++;
        }

        // Record alert
        if (alertGenerated) {
            AASS.data.alerts.unshift(alertGenerated);
            if (AASS.data.alerts.length > 30) AASS.data.alerts.pop();
            AASS.showToast(
                `Adaptive Engine Response: ${actionTaken} for [${username}] from IP ${ip}`,
                alertGenerated.risk.toLowerCase(),
                alertGenerated.type
            );
        }

        // Trigger UI refreshes if listeners registered
        window.dispatchEvent(new CustomEvent('aass:event', { detail: { activity: activityItem, alert: alertGenerated } }));

        return activityItem;
    },

    // Start automated high-speed simulated brute-force attack
    startSimulation: function(speedMs = 1200) {
        if (AASS_Simulator.isRunning) return;
        AASS_Simulator.isRunning = true;
        AASS.showToast('Brute-force attack simulation initiated. Watch real-time detection in action!', 'warning', 'Simulation Started');

        const simBtn = document.getElementById('btn-toggle-sim');
        if (simBtn) {
            simBtn.innerHTML = `<i data-lucide="square"></i> Stop Simulation`;
            simBtn.className = 'btn-danger-custom btn-sm-custom';
            AASS.initLucide();
        }

        AASS_Simulator.intervalId = setInterval(() => {
            AASS_Simulator.simulateSingleAttempt(false, AASS_Simulator.targetUsername);
        }, speedMs);
    },

    stopSimulation: function() {
        if (!AASS_Simulator.isRunning) return;
        clearInterval(AASS_Simulator.intervalId);
        AASS_Simulator.isRunning = false;
        AASS.showToast('Attack simulation stopped.', 'info');

        const simBtn = document.getElementById('btn-toggle-sim');
        if (simBtn) {
            simBtn.innerHTML = `<i data-lucide="play"></i> Simulate Attack`;
            simBtn.className = 'btn-primary-custom btn-sm-custom';
            AASS.initLucide();
        }
    },

    resetData: function() {
        AASS_Simulator.stopSimulation();
        AASS_Simulator.attackCount = 0;
        AASS.showToast('Simulation metrics reset to baseline state.', 'success');
        window.dispatchEvent(new CustomEvent('aass:reset'));
    }
};

