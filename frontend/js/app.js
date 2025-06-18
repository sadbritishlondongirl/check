/**
 * OneID 2.0 Main Application Module
 * Coordinates all modules and handles global application logic
 */

class OneIDApp {
    constructor() {
        this.initialized = false;
        this.securityEnforced = false;
        this.webAuthnSupported = false;
        this.offlineMode = false;
        this.serviceWorkerRegistered = false;
        this.updateAvailable = false;
        this.installPrompt = null;
        this.securityChecks = {
            csp: false,
            https: false,
            integrity: false,
            tampering: false,
            serviceWorker: false
        };
        this.rateLimiters = new Map();
        this.failedRequests = [];
    }

    // === APPLICATION INITIALIZATION ===

    /**
     * Initialize OneID application
     */
    async init() {
        try {
            console.log('🛡️ OneID 2.0 - Initializing...');

            // Security checks first
            await this.performSecurityChecks();
            
            // Initialize core modules
            await this.initializeModules();
            
            // Setup global event handlers
            this.setupGlobalEventHandlers();
            
            // Setup security monitoring
            this.setupSecurityMonitoring();
            
            // Check WebAuthn support
            this.checkWebAuthnSupport();
            
            // Initialize authentication manager
            await authManager.init();
            
            // Setup keyboard shortcuts
            this.setupKeyboardShortcuts();
            
            // Setup offline detection
            this.setupOfflineHandling();
            
            // Register Service Worker
            await this.registerServiceWorker();
            
            // Setup PWA features
            this.setupPWAFeatures();

            this.initialized = true;
            console.log('✅ OneID 2.0 - Initialized successfully');

        } catch (error) {
            console.error('❌ OneID 2.0 - Initialization failed:', error);
            this.showCriticalError('Application initialization failed', error.message);
        }
    }

    // === SECURITY ENFORCEMENT ===

    /**
     * Perform comprehensive security checks
     */
    async performSecurityChecks() {
        console.log('🔒 Performing security checks...');

        // Check HTTPS
        this.securityChecks.https = location.protocol === 'https:' || location.hostname === 'localhost';
        if (!this.securityChecks.https && location.hostname !== 'localhost') {
            throw new Error('OneID requires HTTPS for security');
        }

        // Check for tampering
        this.securityChecks.tampering = await this.checkIntegrity();
        if (!this.securityChecks.tampering) {
            console.warn('⚠️ Potential code tampering detected');
        }

        // Check CSP support
        this.securityChecks.csp = this.checkCSPSupport();
        
        // Enforce security headers
        this.enforceSecurityHeaders();

        this.securityEnforced = true;
        console.log('✅ Security checks completed');
    }

    /**
     * Check code integrity
     */
    async checkIntegrity() {
        try {
            // Basic integrity check - verify core functions exist
            const requiredFunctions = [
                'generateDeviceFingerprint',
                'generateMnemonic',
                'isValidEmail',
                'showToast',
                'oneIdAPI.login',
                'authManager.init',
                'totpManager.initializeSetup'
            ];

            for (const funcPath of requiredFunctions) {
                const func = this.getNestedProperty(window, funcPath);
                if (!func || typeof func !== 'function') {
                    console.warn(`Missing function: ${funcPath}`);
                    return false;
                }
            }

            return true;
        } catch (error) {
            console.error('Integrity check failed:', error);
            return false;
        }
    }

    /**
     * Get nested property from object
     */
    getNestedProperty(obj, path) {
        return path.split('.').reduce((current, prop) => {
            return current && current[prop] !== undefined ? current[prop] : undefined;
        }, obj);
    }

    /**
     * Check CSP support
     */
    checkCSPSupport() {
        // Simple CSP check
        const meta = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
        return !!meta || !!document.querySelector('meta[property="csp-nonce"]');
    }

    /**
     * Enforce security headers
     */
    enforceSecurityHeaders() {
        // Add security meta tags if not present
        this.addMetaTag('X-Content-Type-Options', 'nosniff');
        this.addMetaTag('X-Frame-Options', 'DENY');
        this.addMetaTag('X-XSS-Protection', '1; mode=block');
        this.addMetaTag('Referrer-Policy', 'strict-origin-when-cross-origin');
    }

    /**
     * Add security meta tag
     */
    addMetaTag(name, content) {
        if (!document.querySelector(`meta[http-equiv="${name}"]`)) {
            const meta = document.createElement('meta');
            meta.setAttribute('http-equiv', name);
            meta.setAttribute('content', content);
            document.head.appendChild(meta);
        }
    }

    // === MODULE INITIALIZATION ===

    /**
     * Initialize all application modules
     */
    async initializeModules() {
        console.log('📦 Initializing modules...');

        // Verify all required modules are loaded
        const requiredModules = ['oneIdAPI', 'authManager', 'totpManager'];
        for (const module of requiredModules) {
            if (!window[module]) {
                throw new Error(`Required module ${module} not loaded`);
            }
        }

        // Initialize TOTP manager
        if (window.totpManager) {
            console.log('✅ TOTP Manager ready');
        }

        console.log('✅ All modules initialized');
    }

    // === EVENT HANDLERS ===

    /**
     * Setup global event handlers
     */
    setupGlobalEventHandlers() {
        // Registration step navigation
        this.setupRegistrationHandlers();
        
        // Login and two-factor handlers
        this.setupLoginHandlers();
        
        // Dashboard handlers
        this.setupDashboardHandlers();
        
        // Recovery handlers
        this.setupRecoveryHandlers();
        
        // Global form handlers
        this.setupFormHandlers();
        
        // Error handling
        this.setupErrorHandlers();

        console.log('✅ Event handlers setup complete');
    }

    /**
     * Setup registration event handlers
     */
    setupRegistrationHandlers() {
        // TOTP verification in registration
        const totpVerifyBtn = document.querySelector('#register-step-3 .btn[onclick*="verifyTotpSetup"]');
        if (totpVerifyBtn) {
            totpVerifyBtn.onclick = async () => {
                const code = document.getElementById('totp-verify-code').value;
                try {
                    await totpManager.verifySetupCode(code);
                    document.getElementById('totp-continue-btn').disabled = false;
                } catch (error) {
                    console.error('TOTP verification failed:', error);
                }
            };
        }

        // Generate new phrase button
        window.generateNewPhrase = async () => {
            try {
                showLoading('Generating new phrase...');
                const newPhrase = await generateMnemonic();
                authManager.registrationData.secretPhrase = newPhrase;
                authManager.displaySecretPhrase();
                hideLoading();
                showToast('New secret phrase generated', 'success');
            } catch (error) {
                hideLoading();
                showToast('Failed to generate new phrase', 'error');
            }
        };

        // Download backup codes
        window.downloadBackupCodes = () => totpManager.downloadBackupCodes();
        window.printBackupCodes = () => totpManager.printBackupCodes();

        // Complete registration
        window.completeRegistration = () => authManager.completeRegistration();
    }

    /**
     * Setup login event handlers
     */
    setupLoginHandlers() {
        // Two-factor verification
        window.verifyTwoFactor = () => authManager.verifyTwoFactor();
        window.cancelTwoFactor = () => authManager.cancelTwoFactor();
        
        // Alternative methods
        window.showAlternativeMethods = () => {
            showModal('Alternative Methods', `
                <p>Choose an alternative verification method:</p>
                <div class="alternative-methods">
                    <button class="btn btn-secondary" onclick="requestEmailCode()">📧 Send Email Code</button>
                    <button class="btn btn-secondary" onclick="useBackupCode()">🔐 Use Backup Code</button>
                    <button class="btn btn-secondary" onclick="contactSupport()">📞 Contact Support</button>
                </div>
            `);
        };

        // Request email code
        window.requestEmailCode = async () => {
            try {
                closeModal();
                showLoading('Sending email code...');
                // Implementation would go here
                hideLoading();
                showToast('Email code sent', 'success');
            } catch (error) {
                hideLoading();
                showToast('Failed to send email code', 'error');
            }
        };

        // Use backup code
        window.useBackupCode = () => {
            closeModal();
            authManager.selectTwoFactorMethod('backup_code');
        };
    }

    /**
     * Setup dashboard event handlers
     */
    setupDashboardHandlers() {
        // TOTP management
        window.regenerateTotp = () => totpManager.regenerateSecret();
        window.disableTotp = () => totpManager.disableTOTP();
        
        // Device management
        window.manageDevices = () => this.showDeviceManagement();
        
        // Backup codes
        window.viewBackupCodes = () => this.showBackupCodes();
        window.generateNewBackupCodes = () => this.generateNewBackupCodes();
        
        // Logout
        window.logout = () => authManager.logout();
    }

    /**
     * Setup recovery event handlers
     */
    setupRecoveryHandlers() {
        // Recovery method selection
        window.selectRecoveryMethod = (method) => {
            this.showRecoveryForm(method);
        };
    }

    /**
     * Setup form validation handlers
     */
    setupFormHandlers() {
        // Real-time validation for all inputs
        document.addEventListener('input', (e) => {
            if (e.target.matches('input[type="email"]')) {
                this.validateEmailInput(e.target);
            } else if (e.target.matches('input[name="username"]')) {
                this.validateUsernameInput(e.target);
            } else if (e.target.matches('input[type="password"]')) {
                this.validatePasswordInput(e.target);
            }
        });

        // Prevent form submission on Enter key for security
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' && e.target.matches('input[type="password"]')) {
                const form = e.target.closest('form');
                if (form) {
                    e.preventDefault();
                    const submitBtn = form.querySelector('button[type="submit"], input[type="submit"]');
                    if (submitBtn && !submitBtn.disabled) {
                        submitBtn.click();
                    }
                }
            }
        });
    }

    /**
     * Setup error handlers
     */
    setupErrorHandlers() {
        // Global error handler
        window.addEventListener('error', (e) => {
            console.error('Global error:', e.error);
            this.logSecurityEvent('javascript_error', {
                message: e.message,
                filename: e.filename,
                lineno: e.lineno
            });
        });

        // Unhandled promise rejections
        window.addEventListener('unhandledrejection', (e) => {
            console.error('Unhandled promise rejection:', e.reason);
            this.logSecurityEvent('promise_rejection', {
                reason: e.reason?.toString()
            });
        });

        // Contact support handler
        window.contactSupport = () => {
            showModal('Contact Support', `
                <p>Need help? Contact our support team:</p>
                <div class="support-options">
                    <p>📧 Email: support@obscura.com</p>
                    <p>🌐 Help Center: help.obscura.com</p>
                    <p>📱 Emergency: +1-555-ONEID-HELP</p>
                </div>
                <p><small>Have your username ready when contacting support.</small></p>
            `);
        };
    }

    // === WEBAUTHN INTEGRATION ===

    /**
     * Check WebAuthn support
     */
    checkWebAuthnSupport() {
        this.webAuthnSupported = !!(navigator.credentials && 
            navigator.credentials.create && 
            navigator.credentials.get &&
            window.PublicKeyCredential);
        
        if (this.webAuthnSupported) {
            console.log('✅ WebAuthn supported');
            this.setupWebAuthnHandlers();
        } else {
            console.log('⚠️ WebAuthn not supported');
        }
    }

    /**
     * Setup WebAuthn handlers
     */
    setupWebAuthnHandlers() {
        // Add WebAuthn option to login
        this.addWebAuthnLoginOption();
        
        // Add WebAuthn option to registration
        this.addWebAuthnRegistrationOption();
    }

    /**
     * Add WebAuthn login option
     */
    addWebAuthnLoginOption() {
        const loginForm = document.getElementById('login-form');
        if (loginForm) {
            const webauthnBtn = document.createElement('button');
            webauthnBtn.type = 'button';
            webauthnBtn.className = 'btn btn-secondary webauthn-btn';
            webauthnBtn.innerHTML = '🔐 Sign in with Biometrics';
            webauthnBtn.onclick = () => this.handleWebAuthnLogin();
            
            loginForm.appendChild(webauthnBtn);
        }
    }

    /**
     * Add WebAuthn registration option
     */
    addWebAuthnRegistrationOption() {
        // Add to registration completion
        const step4 = document.getElementById('register-step-4');
        if (step4) {
            const webauthnSetup = document.createElement('div');
            webauthnSetup.className = 'webauthn-setup';
            webauthnSetup.innerHTML = `
                <div class="webauthn-option">
                    <h4>🔐 Biometric Authentication (Optional)</h4>
                    <p>Set up fingerprint, Face ID, or security key for faster login</p>
                    <button class="btn btn-secondary btn-small" onclick="oneIDApp.setupWebAuthn()">
                        Set Up Biometrics
                    </button>
                </div>
            `;
            step4.insertBefore(webauthnSetup, step4.querySelector('.backup-confirm'));
        }
    }

    /**
     * Handle WebAuthn login
     */
    async handleWebAuthnLogin() {
        try {
            showLoading('Preparing biometric authentication...');
            
            const options = await oneIdAPI.getWebAuthnAuthenticationOptions();
            
            hideLoading();
            showLoading('Use your biometric authentication...');
            
            const credential = await navigator.credentials.get({
                publicKey: options
            });
            
            const response = await oneIdAPI.completeWebAuthnAuthentication(credential);
            
            if (response.success) {
                oneIdAPI.setTokens(response.accessToken, response.refreshToken);
                await authManager.loadUserProfile();
                hideLoading();
                showToast('Biometric login successful!', 'success');
                showScreen('dashboard-screen');
            }
            
        } catch (error) {
            hideLoading();
            console.error('WebAuthn login failed:', error);
            showToast('Biometric authentication failed', 'error');
        }
    }

    /**
     * Setup WebAuthn during registration
     */
    async setupWebAuthn() {
        try {
            showLoading('Setting up biometric authentication...');
            
            const options = await oneIdAPI.getWebAuthnRegistrationOptions();
            
            hideLoading();
            showLoading('Follow the prompts on your device...');
            
            const credential = await navigator.credentials.create({
                publicKey: options
            });
            
            await oneIdAPI.completeWebAuthnRegistration(credential);
            
            hideLoading();
            showToast('Biometric authentication setup complete!', 'success');
            
        } catch (error) {
            hideLoading();
            console.error('WebAuthn setup failed:', error);
            showToast('Biometric setup failed: ' + error.message, 'error');
        }
    }

    // === SECURITY MONITORING ===

    /**
     * Setup security monitoring
     */
    setupSecurityMonitoring() {
        // Monitor for suspicious activity
        this.setupTamperingDetection();
        this.setupInputSanitization();
        this.setupRateLimiting();
        
        console.log('✅ Security monitoring active');
    }

    /**
     * Setup tampering detection
     */
    setupTamperingDetection() {
        // Monitor console access
        let devtools = false;
        const threshold = 160;
        
        setInterval(() => {
            if (window.outerHeight - window.innerHeight > threshold || 
                window.outerWidth - window.innerWidth > threshold) {
                if (!devtools) {
                    devtools = true;
                    console.warn('⚠️ Developer tools detected');
                    this.logSecurityEvent('devtools_detected', {
                        timestamp: Date.now(),
                        userAgent: navigator.userAgent
                    });
                }
            } else {
                devtools = false;
            }
        }, 500);

        // Monitor for DOM modifications
        const observer = new MutationObserver((mutations) => {
            mutations.forEach((mutation) => {
                if (mutation.type === 'childList' && mutation.addedNodes.length > 0) {
                    mutation.addedNodes.forEach((node) => {
                        if (node.nodeType === Node.ELEMENT_NODE) {
                            // Check for suspicious script injection
                            if (node.tagName === 'SCRIPT' && !node.src) {
                                console.warn('⚠️ Inline script detected:', node.innerHTML);
                                this.logSecurityEvent('script_injection', {
                                    content: node.innerHTML.substring(0, 100)
                                });
                            }
                        }
                    });
                }
            });
        });

        observer.observe(document.body, {
            childList: true,
            subtree: true
        });
    }

    /**
     * Setup input sanitization
     */
    setupInputSanitization() {
        document.addEventListener('input', (e) => {
            if (e.target.matches('input, textarea')) {
                const sanitized = this.sanitizeInput(e.target.value);
                if (sanitized !== e.target.value) {
                    e.target.value = sanitized;
                    showToast('Input sanitized for security', 'warning');
                }
            }
        });
    }

    /**
     * Sanitize user input
     */
    sanitizeInput(input) {
        // Remove potentially dangerous characters
        return input
            .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
            .replace(/javascript:/gi, '')
            .replace(/on\w+\s*=/gi, '')
            .replace(/data:text\/html/gi, '');
    }

    /**
     * Setup client-side rate limiting
     */
    setupRateLimiting() {
        const rateLimits = new Map();
        
        // Rate limit API calls
        const originalFetch = window.fetch;
        window.fetch = async (...args) => {
            const url = args[0];
            const key = typeof url === 'string' ? url : url.url;
            
            const now = Date.now();
            const limit = rateLimits.get(key);
            
            if (limit && now - limit.lastCall < limit.delay) {
                throw new Error('Rate limit exceeded');
            }
            
            rateLimits.set(key, {
                lastCall: now,
                delay: 1000 // 1 second between calls
            });
            
            return originalFetch.apply(this, args);
        };
    }

    // === VALIDATION METHODS ===

    /**
     * Validate email input
     */
    validateEmailInput(input) {
        const isValid = isValidEmail(input.value);
        this.updateInputValidation(input, isValid, 'Please enter a valid email address');
    }

    /**
     * Validate username input
     */
    validateUsernameInput(input) {
        const isValid = isValidUsername(input.value);
        this.updateInputValidation(input, isValid, 'Username must be 3-20 characters, letters and numbers only');
    }

    /**
     * Validate password input
     */
    validatePasswordInput(input) {
        const strength = getPasswordStrength(input.value);
        const isValid = strength.strength !== 'weak';
        this.updateInputValidation(input, isValid, strength.feedback.join(', '));
        
        // Update password strength indicator
        updatePasswordStrength(input.value);
    }

    /**
     * Update input validation UI
     */
    updateInputValidation(input, isValid, message) {
        input.classList.toggle('invalid', !isValid);
        input.classList.toggle('valid', isValid);
        
        // Update error message
        let errorEl = input.parentElement.querySelector('.error-message');
        if (!errorEl) {
            errorEl = document.createElement('div');
            errorEl.className = 'error-message';
            input.parentElement.appendChild(errorEl);
        }
        
        errorEl.textContent = isValid ? '' : message;
        errorEl.style.display = isValid ? 'none' : 'block';
    }

    // === KEYBOARD SHORTCUTS ===

    /**
     * Setup keyboard shortcuts
     */
    setupKeyboardShortcuts() {
        document.addEventListener('keydown', (e) => {
            // Ctrl/Cmd + K for quick actions
            if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
                e.preventDefault();
                this.showQuickActions();
            }
            
            // Escape to close modals
            if (e.key === 'Escape') {
                closeModal();
            }
            
            // Alt + L for logout
            if (e.altKey && e.key === 'l' && authManager.currentUser) {
                e.preventDefault();
                authManager.logout();
            }
        });
    }

    /**
     * Show quick actions menu
     */
    showQuickActions() {
        const actions = [];
        
        if (authManager.currentUser) {
            actions.push(
                { text: '🏠 Dashboard', action: () => showScreen('dashboard-screen') },
                { text: '🔑 Change Password', action: () => this.showPasswordChange() },
                { text: '📱 Manage TOTP', action: () => totpManager.regenerateSecret() },
                { text: '💻 Manage Devices', action: () => this.showDeviceManagement() },
                { text: '🚪 Logout', action: () => authManager.logout() }
            );
        } else {
            actions.push(
                { text: '🔑 Sign In', action: () => showScreen('login-screen') },
                { text: '📝 Register', action: () => showScreen('register-screen') },
                { text: '🔄 Recovery', action: () => showScreen('recovery-screen') }
            );
        }
        
        const actionsHtml = actions.map(action => 
            `<button class="quick-action-btn" data-action="${action.text}">${action.text}</button>`
        ).join('');
        
        showModal('Quick Actions', `<div class="quick-actions">${actionsHtml}</div>`);
        
        // Add event listeners
        document.querySelectorAll('.quick-action-btn').forEach((btn, index) => {
            btn.onclick = () => {
                closeModal();
                actions[index].action();
            };
        });
    }

    // === OFFLINE HANDLING ===

    /**
     * Setup offline detection and handling
     */
    setupOfflineHandling() {
        window.addEventListener('online', () => {
            this.offlineMode = false;
            showToast('Connection restored', 'success');
            authManager.updateConnectionStatus(true);
        });
        
        window.addEventListener('offline', () => {
            this.offlineMode = true;
            showToast('You are offline. Some features may be limited.', 'warning');
            authManager.updateConnectionStatus(false);
        });
        
        // Initial status
        this.offlineMode = !navigator.onLine;
    }

    // === UTILITY METHODS ===

    /**
     * Show device management
     */
    async showDeviceManagement() {
        try {
            showLoading('Loading devices...');
            const devices = await oneIdAPI.getDevices();
            hideLoading();
            
            const devicesList = devices.map(device => `
                <div class="device-management-item">
                    <div class="device-info">
                        <span class="device-name">${device.name}</span>
                        <span class="device-type">${device.type}</span>
                        <span class="device-last-seen">Last seen: ${this.formatDate(device.lastSeen)}</span>
                    </div>
                    <div class="device-actions">
                        ${device.isCurrent ? '<span class="current-device">Current Device</span>' : 
                          `<button class="btn btn-danger btn-small" onclick="oneIDApp.revokeDevice('${device.id}')">Revoke</button>`}
                    </div>
                </div>
            `).join('');
            
            showModal('Device Management', `
                <div class="device-management">
                    ${devicesList}
                    <div class="device-actions-footer">
                        <button class="btn btn-secondary" onclick="oneIDApp.addNewDevice()">Add New Device</button>
                    </div>
                </div>
            `);
            
        } catch (error) {
            hideLoading();
            showToast('Failed to load devices: ' + error.message, 'error');
        }
    }

    /**
     * Show backup codes
     */
    async showBackupCodes() {
        try {
            const codes = await totpManager.generateBackupCodes();
            totpManager.displayBackupCodes(codes);
            
            showModal('Backup Codes', `
                <div class="backup-codes-modal">
                    <div class="warning-box">
                        <strong>⚠️ Important:</strong> These codes can only be used once each. Save them securely.
                    </div>
                    <div class="backup-codes-display" id="modal-backup-codes"></div>
                </div>
            `);
            
            // Display codes in modal
            const modalCodesEl = document.getElementById('modal-backup-codes');
            codes.forEach((code, index) => {
                const codeEl = document.createElement('div');
                codeEl.className = 'backup-code';
                codeEl.textContent = `${index + 1}. ${totpManager.formatBackupCode(code)}`;
                modalCodesEl.appendChild(codeEl);
            });
            
        } catch (error) {
            showToast('Failed to generate backup codes: ' + error.message, 'error');
        }
    }

    /**
     * Generate new backup codes
     */
    async generateNewBackupCodes() {
        const confirmed = await this.confirmAction(
            'Generate New Backup Codes',
            'This will invalidate all existing backup codes. Continue?'
        );
        
        if (confirmed) {
            await this.showBackupCodes();
        }
    }

    /**
     * Show password change form
     */
    showPasswordChange() {
        const form = `
            <form id="password-change-form">
                <div class="form-group">
                    <label for="current-password">Current Password</label>
                    <input type="password" id="current-password" required>
                </div>
                <div class="form-group">
                    <label for="new-password">New Password</label>
                    <input type="password" id="new-password" required>
                    <div class="password-strength" id="new-password-strength">
                        <div class="strength-bar">
                            <div class="strength-fill"></div>
                        </div>
                        <span class="strength-text">Enter a password</span>
                    </div>
                </div>
                <div class="form-group">
                    <label for="confirm-password">Confirm New Password</label>
                    <input type="password" id="confirm-password" required>
                </div>
            </form>
        `;
        
        showModal('Change Password', form, [
            {
                text: 'Cancel',
                type: 'btn-secondary',
                onclick: () => closeModal()
            },
            {
                text: 'Change Password',
                type: 'btn-primary',
                onclick: () => this.handlePasswordChange()
            }
        ]);
        
        // Setup password strength checking
        document.getElementById('new-password').addEventListener('input', (e) => {
            updatePasswordStrength(e.target.value, 'new-password-strength');
        });
    }

    /**
     * Handle password change
     */
    async handlePasswordChange() {
        const currentPassword = document.getElementById('current-password').value;
        const newPassword = document.getElementById('new-password').value;
        const confirmPassword = document.getElementById('confirm-password').value;
        
        if (newPassword !== confirmPassword) {
            showToast('New passwords do not match', 'error');
            return;
        }
        
        const strength = getPasswordStrength(newPassword);
        if (strength.strength === 'weak') {
            showToast('New password is too weak', 'error');
            return;
        }
        
        try {
            showLoading('Changing password...');
            await oneIdAPI.changePassword(currentPassword, newPassword);
            
            closeModal();
            hideLoading();
            showToast('Password changed successfully', 'success');
            
        } catch (error) {
            hideLoading();
            showToast('Failed to change password: ' + error.message, 'error');
        }
    }

    /**
     * Show recovery form for selected method
     */
    showRecoveryForm(method) {
        const forms = {
            'email': `
                <div class="recovery-form">
                    <h3>📧 Email Recovery</h3>
                    <p>Enter your email address to receive a recovery link</p>
                    <div class="form-group">
                        <label for="recovery-email">Email Address</label>
                        <input type="email" id="recovery-email" required>
                    </div>
                    <button class="btn btn-primary" onclick="oneIDApp.startEmailRecovery()">Send Recovery Link</button>
                </div>
            `,
            'secret-phrase': `
                <div class="recovery-form">
                    <h3>🔑 Secret Phrase Recovery</h3>
                    <p>Enter your secret phrase to recover your account</p>
                    <div class="form-group">
                        <label for="recovery-identifier">Email or Username</label>
                        <input type="text" id="recovery-identifier" required>
                    </div>
                    <div class="form-group">
                        <label for="recovery-phrase">Secret Phrase</label>
                        <textarea id="recovery-phrase" rows="3" placeholder="Enter your 12-word secret phrase" required></textarea>
                    </div>
                    <div class="form-group">
                        <label for="recovery-new-password">New Password</label>
                        <input type="password" id="recovery-new-password" required>
                    </div>
                    <button class="btn btn-primary" onclick="oneIDApp.startPhraseRecovery()">Recover Account</button>
                </div>
            `,
            'trusted-contacts': `
                <div class="recovery-form">
                    <h3>👥 Trusted Contacts Recovery</h3>
                    <p>Recovery via trusted contacts requires manual verification</p>
                    <div class="contact-info">
                        <p>This process requires multiple trusted contacts to verify your identity.</p>
                        <p>Please contact support to initiate this recovery method.</p>
                    </div>
                    <button class="btn btn-secondary" onclick="contactSupport()">Contact Support</button>
                </div>
            `
        };
        
        const recoveryFormEl = document.getElementById('recovery-form');
        recoveryFormEl.innerHTML = forms[method] || '<p>Invalid recovery method</p>';
        recoveryFormEl.classList.remove('hidden');
    }

    /**
     * Start email recovery
     */
    async startEmailRecovery() {
        try {
            const email = document.getElementById('recovery-email').value;
            if (!isValidEmail(email)) {
                showToast('Please enter a valid email address', 'error');
                return;
            }
            
            showLoading('Sending recovery email...');
            await oneIdAPI.startRecovery(email, 'email');
            
            hideLoading();
            showToast('Recovery email sent. Check your inbox.', 'success');
            
        } catch (error) {
            hideLoading();
            showToast('Failed to send recovery email: ' + error.message, 'error');
        }
    }

    /**
     * Start phrase recovery
     */
    async startPhraseRecovery() {
        try {
            const identifier = document.getElementById('recovery-identifier').value;
            const phrase = document.getElementById('recovery-phrase').value;
            const newPassword = document.getElementById('recovery-new-password').value;
            
            if (!identifier || !phrase || !newPassword) {
                showToast('Please fill in all fields', 'error');
                return;
            }
            
            const phraseWords = phrase.trim().split(/\s+/);
            if (phraseWords.length !== 12) {
                showToast('Secret phrase must be exactly 12 words', 'error');
                return;
            }
            
            showLoading('Recovering account...');
            const response = await oneIdAPI.completeSecretPhraseRecovery(identifier, phraseWords, newPassword);
            
            oneIdAPI.setTokens(response.accessToken, response.refreshToken);
            await authManager.loadUserProfile();
            
            hideLoading();
            showToast('Account recovered successfully!', 'success');
            showScreen('dashboard-screen');
            
        } catch (error) {
            hideLoading();
            showToast('Recovery failed: ' + error.message, 'error');
        }
    }

    /**
     * Revoke device
     */
    async revokeDevice(deviceId) {
        const confirmed = await this.confirmAction(
            'Revoke Device',
            'This will remove the device from your trusted devices. The device will need to complete 2FA on next login.'
        );
        
        if (confirmed) {
            try {
                await oneIdAPI.revokeDevice(deviceId);
                showToast('Device revoked successfully', 'success');
                closeModal();
                this.showDeviceManagement(); // Refresh list
            } catch (error) {
                showToast('Failed to revoke device: ' + error.message, 'error');
            }
        }
    }

    /**
     * Log security event
     */
    logSecurityEvent(type, details) {
        try {
            oneIdAPI.reportSecurityIncident(type, JSON.stringify(details));
        } catch (error) {
            console.error('Failed to log security event:', error);
        }
    }

    /**
     * Show critical error
     */
    showCriticalError(title, message) {
        document.body.innerHTML = `
            <div class="critical-error">
                <div class="error-container">
                    <h1>🚨 ${title}</h1>
                    <p>${message}</p>
                    <button onclick="location.reload()" class="btn btn-primary">Reload Application</button>
                </div>
            </div>
        `;
    }

    /**
     * Confirm action with user
     */
    async confirmAction(title, message) {
        return new Promise((resolve) => {
            showModal(title, message, [
                {
                    text: 'Cancel',
                    type: 'btn-secondary',
                    onclick: () => {
                        closeModal();
                        resolve(false);
                    }
                },
                {
                    text: 'Confirm',
                    type: 'btn-danger',
                    onclick: () => {
                        closeModal();
                        resolve(true);
                    }
                }
            ]);
        });
    }

    /**
     * Format date for display
     */
    formatDate(timestamp) {
        return new Date(timestamp).toLocaleDateString() + ' ' + 
               new Date(timestamp).toLocaleTimeString();
    }

    // === SERVICE WORKER & PWA ===

    /**
     * Register Service Worker
     */
    async registerServiceWorker() {
        if ('serviceWorker' in navigator) {
            try {
                console.log('🔧 Registering Service Worker...');
                
                const registration = await navigator.serviceWorker.register('/sw.js');
                this.serviceWorkerRegistered = true;
                this.securityChecks.serviceWorker = true;
                
                // Handle updates
                registration.addEventListener('updatefound', () => {
                    const newWorker = registration.installing;
                    if (newWorker) {
                        newWorker.addEventListener('statechange', () => {
                            if (newWorker.state === 'installed' && navigator.serviceWorker.controller) {
                                this.updateAvailable = true;
                                this.showUpdateNotification();
                            }
                        });
                    }
                });
                
                // Check for existing updates
                if (registration.waiting) {
                    this.updateAvailable = true;
                    this.showUpdateNotification();
                }
                
                console.log('✅ Service Worker registered successfully');
                
            } catch (error) {
                console.error('❌ Service Worker registration failed:', error);
                this.logSecurityEvent('sw_registration_failed', { error: error.message });
            }
        } else {
            console.warn('⚠️ Service Worker not supported');
        }
    }

    /**
     * Setup PWA features
     */
    setupPWAFeatures() {
        // Install prompt
        window.addEventListener('beforeinstallprompt', (e) => {
            e.preventDefault();
            this.installPrompt = e;
            this.showInstallButton();
        });
        
        // App installed
        window.addEventListener('appinstalled', () => {
            this.installPrompt = null;
            this.hideInstallButton();
            showToast('OneID installed successfully!', 'success');
            this.logSecurityEvent('pwa_installed', { timestamp: Date.now() });
        });
        
        // Standalone mode detection
        if (window.matchMedia('(display-mode: standalone)').matches) {
            console.log('✅ Running in PWA mode');
            document.body.classList.add('pwa-mode');
        }
        
        // Handle PWA navigation
        this.setupPWANavigation();
        
        console.log('✅ PWA features setup complete');
    }

    /**
     * Show install button
     */
    showInstallButton() {
        // Add install button to header if not already present
        if (!document.getElementById('install-btn')) {
            const installBtn = document.createElement('button');
            installBtn.id = 'install-btn';
            installBtn.className = 'btn btn-primary btn-small install-btn';
            installBtn.innerHTML = '📱 Install App';
            installBtn.onclick = () => this.promptInstall();
            
            const authStatus = document.getElementById('auth-status');
            authStatus.parentElement.insertBefore(installBtn, authStatus);
        }
    }

    /**
     * Hide install button
     */
    hideInstallButton() {
        const installBtn = document.getElementById('install-btn');
        if (installBtn) {
            installBtn.remove();
        }
    }

    /**
     * Prompt PWA installation
     */
    async promptInstall() {
        if (this.installPrompt) {
            try {
                const result = await this.installPrompt.prompt();
                console.log('Install prompt result:', result.outcome);
                
                if (result.outcome === 'accepted') {
                    this.logSecurityEvent('pwa_install_accepted', { timestamp: Date.now() });
                } else {
                    this.logSecurityEvent('pwa_install_dismissed', { timestamp: Date.now() });
                }
                
            } catch (error) {
                console.error('Install prompt failed:', error);
            }
        }
    }

    /**
     * Show update notification
     */
    showUpdateNotification() {
        showModal('App Update Available', `
            <div class="update-notification">
                <p>A new version of OneID is available with security improvements and new features.</p>
                <p><strong>Recommended:</strong> Update now to ensure optimal security.</p>
            </div>
        `, [
            {
                text: 'Later',
                type: 'btn-secondary',
                onclick: () => closeModal()
            },
            {
                text: 'Update Now',
                type: 'btn-primary',
                onclick: () => this.applyUpdate()
            }
        ]);
    }

    /**
     * Apply service worker update
     */
    async applyUpdate() {
        if (navigator.serviceWorker.controller) {
            try {
                closeModal();
                showLoading('Updating application...');
                
                // Tell the waiting service worker to skip waiting
                const registration = await navigator.serviceWorker.getRegistration();
                if (registration && registration.waiting) {
                    registration.waiting.postMessage({ type: 'SKIP_WAITING' });
                }
                
                // Reload the page to activate the new service worker
                setTimeout(() => {
                    window.location.reload();
                }, 1000);
                
            } catch (error) {
                hideLoading();
                showToast('Update failed: ' + error.message, 'error');
            }
        }
    }

    /**
     * Setup PWA navigation handling
     */
    setupPWANavigation() {
        // Handle app launch with query parameters
        const urlParams = new URLSearchParams(window.location.search);
        const screen = urlParams.get('screen');
        const action = urlParams.get('action');
        
        if (screen) {
            setTimeout(() => {
                showScreen(screen + '-screen');
            }, 100);
        }
        
        if (action === 'auth') {
            const data = urlParams.get('data');
            if (data) {
                this.handleProtocolAuth(data);
            }
        }
        
        // Handle notification clicks
        if (urlParams.get('notification') === 'security') {
            setTimeout(() => {
                showScreen('dashboard-screen');
                showToast('Security notification opened', 'info');
            }, 100);
        }
    }

    /**
     * Handle protocol-based authentication
     */
    handleProtocolAuth(data) {
        try {
            const authData = JSON.parse(decodeURIComponent(data));
            console.log('Protocol auth data:', authData);
            
            // Handle different auth protocols
            if (authData.type === 'recovery') {
                showScreen('recovery-screen');
                showToast('Recovery link opened', 'info');
            } else if (authData.type === 'verification') {
                // Handle email verification
                this.handleEmailVerification(authData.token);
            }
            
        } catch (error) {
            console.error('Failed to parse protocol auth data:', error);
        }
    }

    /**
     * Handle email verification
     */
    async handleEmailVerification(token) {
        try {
            showLoading('Verifying email...');
            await oneIdAPI.verifyEmail(token);
            
            hideLoading();
            showToast('Email verified successfully!', 'success');
            
        } catch (error) {
            hideLoading();
            showToast('Email verification failed: ' + error.message, 'error');
        }
    }

    /**
     * Get cache statistics
     */
    async getCacheStats() {
        if (navigator.serviceWorker.controller) {
            try {
                const channel = new MessageChannel();
                
                return new Promise((resolve) => {
                    channel.port1.onmessage = (event) => {
                        resolve(event.data);
                    };
                    
                    navigator.serviceWorker.controller.postMessage({
                        type: 'CACHE_STATS'
                    }, [channel.port2]);
                });
                
            } catch (error) {
                console.error('Failed to get cache stats:', error);
                return {};
            }
        }
        return {};
    }

    /**
     * Clear application cache
     */
    async clearCache() {
        if (navigator.serviceWorker.controller) {
            try {
                const channel = new MessageChannel();
                
                return new Promise((resolve) => {
                    channel.port1.onmessage = (event) => {
                        resolve(event.data.success);
                    };
                    
                    navigator.serviceWorker.controller.postMessage({
                        type: 'CLEAR_CACHE'
                    }, [channel.port2]);
                });
                
            } catch (error) {
                console.error('Failed to clear cache:', error);
                return false;
            }
        }
        return false;
    }

    /**
     * Enable push notifications
     */
    async enablePushNotifications() {
        if ('Notification' in window && 'serviceWorker' in navigator) {
            try {
                const permission = await Notification.requestPermission();
                
                if (permission === 'granted') {
                    const registration = await navigator.serviceWorker.getRegistration();
                    if (registration) {
                        const subscription = await registration.pushManager.subscribe({
                            userVisibleOnly: true,
                            applicationServerKey: await this.getVapidKey()
                        });
                        
                        await oneIdAPI.subscribeToPushNotifications(subscription);
                        showToast('Push notifications enabled', 'success');
                        return true;
                    }
                } else {
                    showToast('Push notifications denied', 'warning');
                }
                
            } catch (error) {
                console.error('Failed to enable push notifications:', error);
                showToast('Failed to enable notifications: ' + error.message, 'error');
            }
        }
        return false;
    }

    /**
     * Get VAPID key for push notifications
     */
    async getVapidKey() {
        try {
            const response = await oneIdAPI.getVapidKey();
            return response.key;
        } catch (error) {
            console.error('Failed to get VAPID key:', error);
            throw error;
        }
    }

    /**
     * Show PWA info modal
     */
    showPWAInfo() {
        const features = [
            '📱 Install as native app',
            '🔒 Offline security features', 
            '📬 Push notifications for security alerts',
            '⚡ Faster loading and performance',
            '🔄 Automatic updates',
            '💾 Smart caching for reliability'
        ];
        
        const featuresHtml = features.map(feature => `<li>${feature}</li>`).join('');
        
        showModal('OneID PWA Features', `
            <div class="pwa-info">
                <p>OneID 2.0 is a Progressive Web App with enhanced capabilities:</p>
                <ul class="pwa-features">${featuresHtml}</ul>
                <div class="pwa-actions">
                    ${this.installPrompt ? '<button class="btn btn-primary" onclick="oneIDApp.promptInstall()">📱 Install Now</button>' : ''}
                    <button class="btn btn-secondary" onclick="oneIDApp.enablePushNotifications()">🔔 Enable Notifications</button>
                </div>
            </div>
        `);
    }
}

// Global app instance
const oneIDApp = new OneIDApp();

// Export for global use
window.oneIDApp = oneIDApp;

// Auto-initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => oneIDApp.init());
} else {
    oneIDApp.init();
}
