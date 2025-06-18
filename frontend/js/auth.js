/**
 * OneID 2.0 Authentication Module
 * Handles user authentication flows and security features
 */

class AuthManager {
    constructor() {
        this.currentUser = null;
        this.twoFactorSession = null;
        this.registrationData = {};
        this.currentStep = 1;
        this.maxSteps = 4;
    }

    // === INITIALIZATION ===

    /**
     * Initialize authentication manager
     */
    async init() {
        // Check if user is already authenticated
        if (oneIdAPI.isAuthenticated()) {
            try {
                await this.loadUserProfile();
                showScreen('dashboard-screen');
                this.updateConnectionStatus(true);
            } catch (error) {
                console.warn('Failed to load user profile:', error);
                oneIdAPI.clearTokens();
                showScreen('welcome-screen');
            }
        } else {
            showScreen('welcome-screen');
        }

        // Set up event listeners
        this.setupEventListeners();
        
        // Test server connection
        this.testConnection();
    }

    /**
     * Setup event listeners for authentication forms
     */
    setupEventListeners() {
        // Registration form handlers
        document.getElementById('register-form-1')?.addEventListener('submit', (e) => {
            e.preventDefault();
            this.handleRegistrationStep1();
        });

        // Login form handler
        document.getElementById('login-form')?.addEventListener('submit', (e) => {
            e.preventDefault();
            this.handleLogin();
        });

        // Password strength checker
        document.getElementById('register-password')?.addEventListener('input', (e) => {
            updatePasswordStrength(e.target.value);
        });

        // Checkbox handlers for registration steps
        document.getElementById('phrase-saved-check')?.addEventListener('change', (e) => {
            document.getElementById('phrase-continue-btn').disabled = !e.target.checked;
        });

        document.getElementById('backup-saved-check')?.addEventListener('change', (e) => {
            document.getElementById('backup-continue-btn').disabled = !e.target.checked;
        });
    }

    // === REGISTRATION FLOW ===

    /**
     * Handle registration step 1 - Basic information
     */
    async handleRegistrationStep1() {
        try {
            showLoading('Validating information...');

            const formData = new FormData(document.getElementById('register-form-1'));
            const email = formData.get('email');
            const username = formData.get('username');
            const password = formData.get('password');

            // Validate input
            if (!isValidEmail(email)) {
                throw new Error('Please enter a valid email address');
            }

            if (!isValidUsername(username)) {
                throw new Error('Username must be 3-20 characters, letters and numbers only');
            }

            const passwordStrength = getPasswordStrength(password);
            if (passwordStrength.strength === 'weak') {
                throw new Error('Password is too weak. Please choose a stronger password.');
            }

            // Store registration data
            this.registrationData = { email, username, password };

            // Generate secret phrase
            this.registrationData.secretPhrase = await generateMnemonic();

            hideLoading();
            this.showRegistrationStep(2);

        } catch (error) {
            hideLoading();
            showToast(error.message, 'error');
        }
    }

    /**
     * Show registration step
     */
    showRegistrationStep(step) {
        // Hide all steps
        document.querySelectorAll('.register-step').forEach(stepEl => {
            stepEl.classList.remove('active');
        });

        // Show target step
        document.getElementById(`register-step-${step}`).classList.add('active');

        // Update step indicator
        document.getElementById('register-step').textContent = step;
        this.currentStep = step;

        // Handle step-specific logic
        if (step === 2) {
            this.displaySecretPhrase();
        } else if (step === 3) {
            this.setupTOTPStep();
        } else if (step === 4) {
            this.displayBackupCodes();
        }
    }

    /**
     * Display secret phrase in step 2
     */
    displaySecretPhrase() {
        const phraseWordsEl = document.getElementById('phrase-words');
        phraseWordsEl.innerHTML = '';

        this.registrationData.secretPhrase.forEach((word, index) => {
            const wordEl = document.createElement('div');
            wordEl.className = 'phrase-word';
            wordEl.textContent = `${index + 1}. ${word}`;
            phraseWordsEl.appendChild(wordEl);
        });
    }

    /**
     * Setup TOTP step
     */
    async setupTOTPStep() {
        try {
            showLoading('Generating TOTP secret...');

            // Generate TOTP setup
            const totpSetup = await oneIdAPI.setupTOTP();
            this.registrationData.totpSecret = totpSetup.secret;

            // Generate QR code
            const qrCodeEl = document.getElementById('qr-code');
            QRCode.toCanvas(qrCodeEl, totpSetup.qrCodeUrl, {
                width: 200,
                margin: 2,
                color: {
                    dark: '#1d1d1f',
                    light: '#ffffff'
                }
            });

            hideLoading();

        } catch (error) {
            hideLoading();
            showToast('Failed to setup TOTP: ' + error.message, 'error');
        }
    }

    /**
     * Verify TOTP setup
     */
    async verifyTotpSetup() {
        try {
            const code = document.getElementById('totp-verify-code').value;
            
            if (!code || code.length !== 6) {
                throw new Error('Please enter a valid 6-digit code');
            }

            showLoading('Verifying TOTP code...');

            await oneIdAPI.verifyTOTPSetup(this.registrationData.totpSecret, code);
            
            document.getElementById('totp-continue-btn').disabled = false;
            showToast('TOTP verified successfully!', 'success');
            hideLoading();

        } catch (error) {
            hideLoading();
            showToast('Invalid TOTP code: ' + error.message, 'error');
        }
    }

    /**
     * Display backup codes in step 4
     */
    async displayBackupCodes() {
        try {
            showLoading('Generating backup codes...');

            const backupCodes = await oneIdAPI.generateBackupCodes();
            this.registrationData.backupCodes = backupCodes.codes;

            const backupCodesEl = document.getElementById('backup-codes-list');
            backupCodesEl.innerHTML = '';

            backupCodes.codes.forEach(code => {
                const codeEl = document.createElement('div');
                codeEl.className = 'backup-code';
                codeEl.textContent = code;
                backupCodesEl.appendChild(codeEl);
            });

            hideLoading();

        } catch (error) {
            hideLoading();
            showToast('Failed to generate backup codes: ' + error.message, 'error');
        }
    }

    /**
     * Complete registration
     */
    async completeRegistration() {
        try {
            showLoading('Creating your account...');

            const response = await oneIdAPI.register(this.registrationData);
            
            // Store tokens
            oneIdAPI.setTokens(response.accessToken, response.refreshToken);
            
            // Load user profile
            await this.loadUserProfile();
            
            hideLoading();
            showToast('Account created successfully! Welcome to OneID 2.0!', 'success');
            showScreen('dashboard-screen');

        } catch (error) {
            hideLoading();
            showToast('Registration failed: ' + error.message, 'error');
        }
    }

    /**
     * Navigate to previous registration step
     */
    prevRegisterStep() {
        if (this.currentStep > 1) {
            this.showRegistrationStep(this.currentStep - 1);
        }
    }

    /**
     * Navigate to next registration step
     */
    nextRegisterStep() {
        if (this.currentStep < this.maxSteps) {
            this.showRegistrationStep(this.currentStep + 1);
        }
    }

    // === LOGIN FLOW ===

    /**
     * Handle user login
     */
    async handleLogin() {
        try {
            showLoading('Signing you in...');

            const formData = new FormData(document.getElementById('login-form'));
            const identifier = formData.get('identifier');
            const password = formData.get('password');
            const trustDevice = document.getElementById('remember-device').checked;

            if (!identifier || !password) {
                throw new Error('Please enter both email/username and password');
            }

            const response = await oneIdAPI.login(identifier, password, trustDevice);

            hideLoading();

            if (response.requiresTwoFactor) {
                this.twoFactorSession = response.twoFactorSession;
                this.showTwoFactorScreen(response.availableMethods);
            } else {
                // Direct login success
                oneIdAPI.setTokens(response.accessToken, response.refreshToken);
                await this.loadUserProfile();
                showToast('Welcome back!', 'success');
                showScreen('dashboard-screen');
            }

        } catch (error) {
            hideLoading();
            showToast('Login failed: ' + error.message, 'error');
        }
    }

    /**
     * Show two-factor authentication screen
     */
    showTwoFactorScreen(availableMethods) {
        showScreen('two-factor-screen');

        const methodsEl = document.getElementById('two-factor-methods');
        methodsEl.innerHTML = '';

        // Create method selector
        const selectorEl = document.createElement('div');
        selectorEl.className = 'method-selector';

        availableMethods.forEach(method => {
            const methodBtn = document.createElement('div');
            methodBtn.className = 'method-btn';
            methodBtn.innerHTML = `
                <div>${this.getTwoFactorMethodIcon(method)}</div>
                <div>${this.getTwoFactorMethodName(method)}</div>
            `;
            methodBtn.onclick = () => this.selectTwoFactorMethod(method);
            selectorEl.appendChild(methodBtn);
        });

        methodsEl.appendChild(selectorEl);

        // Default to first method
        if (availableMethods.length > 0) {
            this.selectTwoFactorMethod(availableMethods[0]);
        }
    }

    /**
     * Select two-factor method
     */
    selectTwoFactorMethod(method) {
        // Update UI
        document.querySelectorAll('.method-btn').forEach(btn => {
            btn.classList.remove('active');
        });
        event.currentTarget.classList.add('active');

        // Update form
        const labelEl = document.getElementById('two-factor-label');
        const hintEl = document.getElementById('two-factor-hint');

        switch (method) {
            case 'totp':
                labelEl.textContent = 'Enter code from authenticator app:';
                hintEl.textContent = 'Open your authenticator app and enter the 6-digit code';
                break;
            case 'email':
                labelEl.textContent = 'Enter code from email:';
                hintEl.textContent = 'Check your email for the verification code';
                break;
            case 'backup_code':
                labelEl.textContent = 'Enter backup code:';
                hintEl.textContent = 'Use one of your saved backup codes';
                break;
        }

        this.selectedTwoFactorMethod = method;
    }

    /**
     * Verify two-factor authentication
     */
    async verifyTwoFactor() {
        try {
            const code = document.getElementById('two-factor-code').value;

            if (!code) {
                throw new Error('Please enter the verification code');
            }

            showLoading('Verifying code...');

            const response = await oneIdAPI.completeTwoFactor(
                this.twoFactorSession.id,
                code,
                this.selectedTwoFactorMethod
            );

            oneIdAPI.setTokens(response.accessToken, response.refreshToken);
            await this.loadUserProfile();

            hideLoading();
            showToast('Welcome back!', 'success');
            showScreen('dashboard-screen');

        } catch (error) {
            hideLoading();
            showToast('Verification failed: ' + error.message, 'error');
        }
    }

    /**
     * Cancel two-factor authentication
     */
    cancelTwoFactor() {
        this.twoFactorSession = null;
        this.selectedTwoFactorMethod = null;
        showScreen('login-screen');
    }

    // === USER MANAGEMENT ===

    /**
     * Load user profile
     */
    async loadUserProfile() {
        try {
            this.currentUser = await oneIdAPI.getUserProfile();
            this.updateConnectionStatus(true);
            
            // Update dashboard with user data
            if (document.getElementById('dashboard-screen').classList.contains('active')) {
                await this.updateDashboard();
            }

        } catch (error) {
            console.error('Failed to load user profile:', error);
            throw error;
        }
    }

    /**
     * Update dashboard with current user data
     */
    async updateDashboard() {
        try {
            // Load OneID Score
            const scoreData = await oneIdAPI.getOneIDScore();
            this.updateSecurityScore(scoreData);

            // Load security events
            const events = await oneIdAPI.getSecurityEvents(5);
            this.updateSecurityEvents(events);

            // Load devices
            const devices = await oneIdAPI.getDevices();
            this.updateDevicesList(devices);

        } catch (error) {
            console.error('Failed to update dashboard:', error);
        }
    }

    /**
     * Update security score display
     */
    updateSecurityScore(scoreData) {
        document.getElementById('security-score').textContent = scoreData.score;
        document.getElementById('security-tier').textContent = scoreData.tier;
        
        const detailsEl = document.getElementById('score-details');
        detailsEl.innerHTML = `
            <p><strong>Account Security:</strong> ${scoreData.factors.account}%</p>
            <p><strong>Device Trust:</strong> ${scoreData.factors.device}%</p>
            <p><strong>Behavior:</strong> ${scoreData.factors.behavior}%</p>
        `;
    }

    /**
     * Update security events list
     */
    updateSecurityEvents(events) {
        const eventsEl = document.getElementById('events-list');
        eventsEl.innerHTML = '';

        events.forEach(event => {
            const eventEl = document.createElement('div');
            eventEl.className = 'event-item';
            eventEl.innerHTML = `
                <div class="event-icon">${this.getEventIcon(event.type)}</div>
                <div class="event-info">
                    <span class="event-title">${event.description}</span>
                    <span class="event-time">${this.formatTime(event.timestamp)}</span>
                    <span class="event-location">📍 ${event.location || 'Unknown location'}</span>
                </div>
            `;
            eventsEl.appendChild(eventEl);
        });
    }

    /**
     * Update devices list
     */
    updateDevicesList(devices) {
        const devicesEl = document.getElementById('devices-list');
        devicesEl.innerHTML = '';

        devices.forEach(device => {
            const deviceEl = document.createElement('div');
            deviceEl.className = `device-item ${device.isCurrent ? 'current' : ''}`;
            deviceEl.innerHTML = `
                <div class="device-info">
                    <span class="device-name">${device.name}</span>
                    <span class="device-type">${this.getDeviceTypeIcon(device.type)} ${device.type}</span>
                </div>
                <span class="device-status ${device.isTrusted ? 'trusted' : 'untrusted'}">
                    ${device.isTrusted ? 'Trusted' : 'Untrusted'}
                </span>
            `;
            devicesEl.appendChild(deviceEl);
        });
    }

    /**
     * Logout user
     */
    async logout() {
        try {
            showLoading('Signing out...');
            await oneIdAPI.logout();
            
            this.currentUser = null;
            this.updateConnectionStatus(false);
            
            hideLoading();
            showToast('Signed out successfully', 'success');
            showScreen('welcome-screen');

        } catch (error) {
            hideLoading();
            showToast('Logout failed: ' + error.message, 'error');
        }
    }

    // === UTILITY METHODS ===

    /**
     * Test server connection
     */
    async testConnection() {
        try {
            // Simple health check
            const response = await fetch(oneIdAPI.baseURL.replace('/api/v1', '/health'));
            this.updateConnectionStatus(response.ok);
        } catch (error) {
            this.updateConnectionStatus(false);
        }
    }

    /**
     * Update connection status indicator
     */
    updateConnectionStatus(isOnline) {
        const indicator = document.getElementById('status-indicator');
        const text = document.getElementById('status-text');
        
        if (isOnline) {
            indicator.className = 'status-indicator online';
            text.textContent = 'Online';
        } else {
            indicator.className = 'status-indicator offline';
            text.textContent = 'Offline';
        }
    }

    /**
     * Get two-factor method icon
     */
    getTwoFactorMethodIcon(method) {
        const icons = {
            'totp': '📱',
            'email': '📧',
            'backup_code': '🔐'
        };
        return icons[method] || '🔒';
    }

    /**
     * Get two-factor method name
     */
    getTwoFactorMethodName(method) {
        const names = {
            'totp': 'Authenticator App',
            'email': 'Email Code',
            'backup_code': 'Backup Code'
        };
        return names[method] || method;
    }

    /**
     * Get event icon
     */
    getEventIcon(type) {
        const icons = {
            'login_success': '✅',
            'login_failed': '❌',
            'password_changed': '🔑',
            'device_added': '📱',
            'totp_enabled': '🔐',
            'recovery_used': '🔄'
        };
        return icons[type] || '📋';
    }

    /**
     * Get device type icon
     */
    getDeviceTypeIcon(type) {
        const icons = {
            'desktop': '🖥️',
            'mobile': '📱',
            'tablet': '📟',
            'browser': '🌐'
        };
        return icons[type] || '💻';
    }

    /**
     * Format timestamp
     */
    formatTime(timestamp) {
        const date = new Date(timestamp);
        const now = new Date();
        const diffMs = now - date;
        const diffMins = Math.floor(diffMs / 60000);
        const diffHours = Math.floor(diffMs / 3600000);
        const diffDays = Math.floor(diffMs / 86400000);

        if (diffMins < 1) return 'Just now';
        if (diffMins < 60) return `${diffMins} minutes ago`;
        if (diffHours < 24) return `${diffHours} hours ago`;
        if (diffDays < 7) return `${diffDays} days ago`;
        
        return date.toLocaleDateString();
    }
}

// Global auth manager instance
const authManager = new AuthManager();

// Export for global use
window.authManager = authManager;

// Auto-initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => authManager.init());
} else {
    authManager.init();
}
