/**
 * Adaptive Authentication Security System (AASS)
 * Dynamic CAPTCHA Verification Module (Module 2)
 */

window.AASS_Captcha = {
    currentSolution: '',
    challengeType: 'alphanumeric', // 'alphanumeric' or 'math'

    init: function(canvasId = 'captchaCanvas', inputId = 'captchaInput') {
        const canvas = document.getElementById(canvasId);
        if (canvas) {
            AASS_Captcha.generate(canvasId);
        }
    },

    // Generate fresh challenge
    generate: async function(canvasId = 'captchaCanvas') {
        const canvas = document.getElementById(canvasId);
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        const width = canvas.width || 180;
        const height = canvas.height || 50;

        // Reset canvas
        ctx.clearRect(0, 0, width, height);

        // Light background
        ctx.fillStyle = '#F8FAFC';
        ctx.fillRect(0, 0, width, height);

        // Draw noise dots
        for (let i = 0; i < 40; i++) {
            ctx.fillStyle = `rgba(${Math.floor(Math.random()*150)}, ${Math.floor(Math.random()*150)}, ${Math.floor(Math.random()*255)}, 0.25)`;
            ctx.beginPath();
            ctx.arc(Math.random() * width, Math.random() * height, Math.random() * 2.5, 0, Math.PI * 2);
            ctx.fill();
        }

        // Draw interference lines
        for (let i = 0; i < 4; i++) {
            ctx.strokeStyle = `rgba(${Math.floor(Math.random()*100)}, ${Math.floor(Math.random()*150)}, 235, 0.4)`;
            ctx.lineWidth = 1.2;
            ctx.beginPath();
            ctx.moveTo(Math.random() * width, Math.random() * height);
            ctx.bezierCurveTo(
                Math.random() * width, Math.random() * height,
                Math.random() * width, Math.random() * height,
                Math.random() * width, Math.random() * height
            );
            ctx.stroke();
        }

        // Generate challenge string (from backend if available)
        var text = '';
        if (AASS.isLiveBackend) {
            try {
                const res = await fetch(`${AASS.apiBase}/auth/captcha?mode=${AASS_Captcha.challengeType}`);
                if (res.ok) {
                    const data = await res.json();
                    text = data.challenge;
                    AASS_Captcha.currentSolution = data.challenge;
                }
            } catch (e) {}
        }

        if (!text) {
            if (AASS_Captcha.challengeType === 'math') {
                const num1 = Math.floor(Math.random() * 20) + 1;
                const num2 = Math.floor(Math.random() * 10) + 1;
                AASS_Captcha.currentSolution = (num1 + num2).toString();
                text = `${num1} + ${num2} = ?`;
            } else {
                const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
                let str = '';
                for (let i = 0; i < 5; i++) {
                    str += chars.charAt(Math.floor(Math.random() * chars.length));
                }
                AASS_Captcha.currentSolution = str;
                text = str;
            }
        }

        // Render characters with distortion
        const charSpacing = width / (text.length + 1);
        ctx.font = 'bold 24px monospace';

        for (let i = 0; i < text.length; i++) {
            ctx.save();
            const char = text[i];
            const x = (i + 0.6) * charSpacing;
            const y = height / 2 + 8 + (Math.random() * 6 - 3);
            const angle = (Math.random() - 0.5) * 0.4;

            ctx.translate(x, y);
            ctx.rotate(angle);
            ctx.fillStyle = i % 2 === 0 ? '#1E293B' : '#2563EB';
            ctx.fillText(char, -8, 0);
            ctx.restore();
        }

        // Clear input box
        const input = document.getElementById('captchaInput');
        if (input) input.value = '';
    },

    // Verify user entered CAPTCHA
    verify: function(userEntry) {
        if (!userEntry) return false;
        const normalizedUser = userEntry.trim().toUpperCase();
        const normalizedSol = AASS_Captcha.currentSolution.toUpperCase();
        return normalizedUser === normalizedSol;
    },

    // Audio CAPTCHA option
    playAudioChallenge: function() {
        if (!AASS_Captcha.currentSolution) return;
        
        // Speak characters using Web Speech Synthesis API
        if ('speechSynthesis' in window) {
            window.speechSynthesis.cancel();
            const textToSpeak = AASS_Captcha.currentSolution.split('').join(' . ');
            const utterance = new SpeechSynthesisUtterance(`Security verification code: ${textToSpeak}`);
            utterance.rate = 0.8;
            utterance.pitch = 1.0;
            window.speechSynthesis.speak(utterance);
        } else {
            AASS.showToast('Speech synthesis not supported in this browser.', 'warning');
        }
    }
};

