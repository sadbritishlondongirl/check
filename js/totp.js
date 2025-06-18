/**
 * OneID 2.0 TOTP Management Module
 * Handles Time-based One-Time Password functionality
 */

class TOTPManager {
    constructor() {
        this.currentSecret = null;
        this.qrCodeElement = null;
        this.isEnabled = false;
        this.backupCodes = [];
    }

    // === TOTP SETUP ===

    /**
     * Initialize TOTP setup during registration
     */
    async initializeSetup() {
        try {
            showLoading('Setting up two-factor authentication...');

            const response = await oneIdAPI.setupTOTP();
            this.currentSecret = response.secret;

            // Generate and display QR code
            await this.displayQRCode(response.qrCodeUrl);
            
            // Show manual entry option
            this.displayManualEntry(response.secret);

            hideLoading();
            return response;

        } catch (error) {
            hideLoading();
            showToast('Failed to setup TOTP: ' + error.message, 'error');
            throw error;
        }
    }

    /**
     * Display QR code for TOTP setup
     */
    async displayQRCode(qrCodeUrl) {
        const qrContainer = document.getElementById('qr-code');
        if (!qrContainer) return;

        // Clear existing content
        qrContainer.innerHTML = '';

        try {
            // Generate QR code with enhanced security settings
            await QRCode.toCanvas(qrContainer, qrCodeUrl, {
                width: 200,
                height: 200,
                margin: 2,
                color: {
                    dark: '#1d1d1f',
                    light: '#ffffff'
                },
                errorCorrectionLevel: 'H', // High error correction
                type: 'image/png'
            });

            // Add security warning
            const warningEl = document.createElement('div');
            warningEl.className = 'qr-warning';
            warningEl.innerHTML = `
                <p><strong>⚠️ Security Notice:</strong></p>
                <p>Keep this QR code private. Don't share or screenshot it.</p>
            `;
            qrContainer.appendChild(warningEl);

        } catch (error) {
            console.error('QR Code generation failed:', error);
            this.displayManualEntry(this.currentSecret);
        }
    }

    /**
     * Display manual entry option as fallback
     */
    displayManualEntry(secret) {
        const qrContainer = document.getElementById('qr-code');
        if (!qrContainer) return;

        const manualEntryEl = document.createElement('div');
        manualEntryEl.className = 'manual-entry';
        manualEntryEl.innerHTML = `
            <div class="manual-entry-toggle">
                <button class="btn btn-secondary btn-small" onclick="totpManager.toggleManualEntry()">
                    📝 Manual Entry
                </button>
            </div>
            <div class="manual-entry-content hidden" id="manual-entry-content">
                <p><strong>Can't scan? Enter this code manually:</strong></p>
                <div class="secret-display">
                    <code id="totp-secret-text">${this.formatSecret(secret)}</code>
                    <button class="btn btn-secondary btn-small" onclick="totpManager.copySecret()">
                        📋 Copy
                    </button>
                </div>
                <div class="manual-instructions">
                    <p><strong>Setup instructions:</strong></p>
                    <ol>
                        <li>Open your authenticator app</li>
                        <li>Choose "Add account" or "+"</li>
                        <li>Select "Enter a setup key"</li>
                        <li>Enter the code above</li>
                        <li>Use "OneID" as account name</li>
                    </ol>
                </div>
            </div>
        `;
        qrContainer.appendChild(manualEntryEl);
    }

    /**
     * Toggle manual entry display
     */
    toggleManualEntry() {
        const content = document.getElementById('manual-entry-content');
        if (content) {
            content.classList.toggle('hidden');
        }
    }

    /**
     * Copy TOTP secret to clipboard
     */
    async copySecret() {
        try {
            const secretText = document.getElementById('totp-secret-text').textContent;
            await navigator.clipboard.writeText(secretText.replace(/\s/g, ''));
            showToast('Secret copied to clipboard', 'success');
        } catch (error) {
            console.error('Copy failed:', error);
            this.fallbackCopySecret();
        }
    }

    /**
     * Fallback copy method for older browsers
     */
    fallbackCopySecret() {
        const secretEl = document.getElementById('totp-secret-text');
        const textArea = document.createElement('textarea');
        textArea.value = secretEl.textContent.replace(/\s/g, '');
        document.body.appendChild(textArea);
        textArea.select();
        try {
            document.execCommand('copy');
            showToast('Secret copied to clipboard', 'success');
        } catch (error) {
            showToast('Please copy the secret manually', 'error');
        }
        document.body.removeChild(textArea);
    }

    /**
     * Format secret for display (groups of 4 characters)
     */
    formatSecret(secret) {
        return secret.replace(/(.{4})/g, '$1 ').trim();
    }

    // === TOTP VERIFICATION ===

    /**
     * Verify TOTP setup code
     */
    async verifySetupCode(code) {
        try {
            if (!code || code.length !== 6 || !/^\d{6}$/.test(code)) {
                throw new Error('Please enter a valid 6-digit code');
            }

            showLoading('Verifying authenticator code...');

            const response = await oneIdAPI.verifyTOTPSetup(this.currentSecret, code);
            
            this.isEnabled = true;
            hideLoading();
            showToast('TOTP setup completed successfully!', 'success');
            
            return response;

        } catch (error) {
            hideLoading();
            showToast('Invalid code. Please try again.', 'error');
            throw error;
        }
    }

    /**
     * Verify TOTP code during login
     */
    async verifyLoginCode(code, sessionId) {
        try {
            if (!code || code.length !== 6 || !/^\d{6}$/.test(code)) {
                throw new Error('Please enter a valid 6-digit code');
            }

            showLoading('Verifying code...');

            const response = await oneIdAPI.completeTwoFactor(sessionId, code, 'totp');
            
            hideLoading();
            return response;

        } catch (error) {
            hideLoading();
            throw error;
        }
    }

    // === BACKUP CODES ===

    /**
     * Generate new backup codes
     */
    async generateBackupCodes() {
        try {
            showLoading('Generating backup codes...');

            const response = await oneIdAPI.generateBackupCodes();
            this.backupCodes = response.codes;

            hideLoading();
            return response.codes;

        } catch (error) {
            hideLoading();
            showToast('Failed to generate backup codes: ' + error.message, 'error');
            throw error;
        }
    }

    /**
     * Display backup codes to user
     */
    displayBackupCodes(codes) {
        const container = document.getElementById('backup-codes-list');
        if (!container) return;

        container.innerHTML = '';

        // Create warning
        const warningEl = document.createElement('div');
        warningEl.className = 'backup-warning';
        warningEl.innerHTML = `
            <div class="warning-box">
                <strong>⚠️ Important:</strong>
                <ul>
                    <li>Each code can only be used once</li>
                    <li>Store these codes in a secure location</li>
                    <li>Don't share them with anyone</li>
                    <li>Generate new codes if you lose these</li>
                </ul>
            </div>
        `;
        container.appendChild(warningEl);

        // Create codes grid
        const codesGrid = document.createElement('div');
        codesGrid.className = 'backup-codes-grid';

        codes.forEach((code, index) => {
            const codeEl = document.createElement('div');
            codeEl.className = 'backup-code';
            codeEl.innerHTML = `
                <span class="code-number">${index + 1}.</span>
                <span class="code-value">${this.formatBackupCode(code)}</span>
            `;
            codesGrid.appendChild(codeEl);
        });

        container.appendChild(codesGrid);

        // Add actions
        const actionsEl = document.createElement('div');
        actionsEl.className = 'backup-actions';
        actionsEl.innerHTML = `
            <button class="btn btn-secondary" onclick="totpManager.downloadBackupCodes()">
                📥 Download as File
            </button>
            <button class="btn btn-secondary" onclick="totpManager.printBackupCodes()">
                🖨️ Print Codes
            </button>
            <button class="btn btn-secondary" onclick="totpManager.copyAllCodes()">
                📋 Copy All
            </button>
        `;
        container.appendChild(actionsEl);
    }

    /**
     * Format backup code for display
     */
    formatBackupCode(code) {
        // Format as XXXX-XXXX for readability
        return code.replace(/(.{4})(.{4})/, '$1-$2');
    }

    /**
     * Download backup codes as text file
     */
    downloadBackupCodes() {
        if (!this.backupCodes.length) return;

        const content = this.generateBackupFileContent();
        const blob = new Blob([content], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);

        const link = document.createElement('a');
        link.href = url;
        link.download = `oneID-backup-codes-${new Date().toISOString().split('T')[0]}.txt`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);

        URL.revokeObjectURL(url);
        showToast('Backup codes downloaded', 'success');
    }

    /**
     * Generate backup file content
     */
    generateBackupFileContent() {
        const timestamp = new Date().toISOString();
        return `OneID 2.0 Backup Codes
Generated: ${timestamp}

IMPORTANT: Keep these codes secure and private!
Each code can only be used once for account recovery.

Backup Codes:
${this.backupCodes.map((code, i) => `${i + 1}. ${this.formatBackupCode(code)}`).join('\n')}

Instructions:
1. Store this file in a secure location
2. Do not share these codes with anyone
3. Use these codes only if you lose access to your authenticator app
4. Generate new codes if you suspect these have been compromised

For support, visit: https://oneid.obscura.com/support
`;
    }

    /**
     * Print backup codes
     */
    printBackupCodes() {
        if (!this.backupCodes.length) return;

        const printWindow = window.open('', '_blank');
        printWindow.document.write(`
            <!DOCTYPE html>
            <html>
            <head>
                <title>OneID Backup Codes</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 20px; }
                    .header { text-align: center; margin-bottom: 30px; }
                    .warning { background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; margin: 20px 0; border-radius: 5px; }
                    .codes { display: grid; grid-template-columns: repeat(2, 1fr); gap: 10px; margin: 20px 0; }
                    .code { font-family: monospace; font-size: 14px; padding: 8px; border: 1px solid #ddd; }
                    .instructions { margin-top: 30px; font-size: 12px; }
                    @media print { .no-print { display: none; } }
                </style>
            </head>
            <body>
                <div class="header">
                    <h1>🛡️ OneID 2.0 Backup Codes</h1>
                    <p>Generated: ${new Date().toLocaleString()}</p>
                </div>
                
                <div class="warning">
                    <strong>⚠️ SECURITY WARNING:</strong>
                    <ul>
                        <li>Keep these codes secure and private</li>
                        <li>Each code can only be used once</li>
                        <li>Store in a safe place separate from your devices</li>
                    </ul>
                </div>
                
                <div class="codes">
                    ${this.backupCodes.map((code, i) => `
                        <div class="code">${i + 1}. ${this.formatBackupCode(code)}</div>
                    `).join('')}
                </div>
                
                <div class="instructions">
                    <h3>Instructions:</h3>
                    <ol>
                        <li>Store this document in a secure location</li>
                        <li>Use these codes only if you lose access to your authenticator app</li>
                        <li>Generate new codes if you suspect these have been compromised</li>
                        <li>For support, visit: https://oneid.obscura.com/support</li>
                    </ol>
                </div>
                
                <button class="no-print" onclick="window.print()" style="margin: 20px 0; padding: 10px 20px;">Print Codes</button>
            </body>
            </html>
        `);

        printWindow.document.close();
        printWindow.focus();
        printWindow.print();
    }

    /**
     * Copy all backup codes to clipboard
     */
    async copyAllCodes() {
        if (!this.backupCodes.length) return;

        try {
            const codesText = this.backupCodes.map((code, i) => 
                `${i + 1}. ${this.formatBackupCode(code)}`
            ).join('\n');

            await navigator.clipboard.writeText(codesText);
            showToast('All backup codes copied to clipboard', 'success');
        } catch (error) {
            console.error('Copy failed:', error);
            showToast('Please copy the codes manually', 'error');
        }
    }

    // === TOTP MANAGEMENT ===

    /**
     * Regenerate TOTP secret
     */
    async regenerateSecret() {
        try {
            const confirmed = await this.confirmAction(
                'Regenerate TOTP Secret',
                'This will invalidate your current authenticator setup. You\'ll need to set up your authenticator app again. Continue?'
            );

            if (!confirmed) return;

            showLoading('Regenerating TOTP secret...');

            const response = await oneIdAPI.regenerateTOTP();
            this.currentSecret = response.secret;

            hideLoading();
            showToast('TOTP secret regenerated. Please set up your authenticator app again.', 'success');

            // Show new QR code setup
            this.showQRSetup(response);

        } catch (error) {
            hideLoading();
            showToast('Failed to regenerate TOTP secret: ' + error.message, 'error');
        }
    }

    /**
     * Disable TOTP
     */
    async disableTOTP() {
        try {
            const confirmed = await this.confirmAction(
                'Disable Two-Factor Authentication',
                'This will remove TOTP protection from your account. This is not recommended. Continue?'
            );

            if (!confirmed) return;

            const password = await this.promptPassword('Enter your password to disable TOTP:');
            if (!password) return;

            showLoading('Disabling TOTP...');

            await oneIdAPI.disableTOTP(password);
            this.isEnabled = false;

            hideLoading();
            showToast('TOTP has been disabled. Your account security is reduced.', 'warning');

            // Update UI
            this.updateTOTPStatus(false);

        } catch (error) {
            hideLoading();
            showToast('Failed to disable TOTP: ' + error.message, 'error');
        }
    }

    /**
     * Update TOTP status in UI
     */
    updateTOTPStatus(enabled) {
        const statusEl = document.getElementById('totp-status');
        if (!statusEl) return;

        statusEl.innerHTML = `
            <div class="status-indicator ${enabled ? 'active' : 'inactive'}"></div>
            <span>${enabled ? 'Enabled' : 'Disabled'}</span>
        `;

        // Update actions
        const actionsEl = statusEl.parentElement.querySelector('.totp-actions');
        if (actionsEl) {
            if (enabled) {
                actionsEl.innerHTML = `
                    <button class="btn btn-secondary btn-small" onclick="totpManager.regenerateSecret()">
                        🔄 Regenerate Secret
                    </button>
                    <button class="btn btn-danger btn-small" onclick="totpManager.disableTOTP()">
                        ❌ Disable TOTP
                    </button>
                `;
            } else {
                actionsEl.innerHTML = `
                    <button class="btn btn-primary btn-small" onclick="totpManager.enableTOTP()">
                        ✅ Enable TOTP
                    </button>
                `;
            }
        }
    }

    // === UTILITY METHODS ===

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
     * Prompt user for password
     */
    async promptPassword(message) {
        return new Promise((resolve) => {
            const modalContent = `
                <p>${message}</p>
                <div class="form-group">
                    <input type="password" id="password-prompt" class="form-control" placeholder="Enter password">
                </div>
            `;

            showModal('Password Required', modalContent, [
                {
                    text: 'Cancel',
                    type: 'btn-secondary',
                    onclick: () => {
                        closeModal();
                        resolve(null);
                    }
                },
                {
                    text: 'Confirm',
                    type: 'btn-primary',
                    onclick: () => {
                        const password = document.getElementById('password-prompt').value;
                        closeModal();
                        resolve(password);
                    }
                }
            ]);

            // Focus password input after modal opens
            setTimeout(() => {
                const passwordInput = document.getElementById('password-prompt');
                if (passwordInput) passwordInput.focus();
            }, 100);
        });
    }

    /**
     * Show QR setup modal
     */
    showQRSetup(response) {
        const modalContent = `
            <div class="qr-setup-modal">
                <p>Scan this QR code with your authenticator app:</p>
                <div id="modal-qr-code" class="qr-code-container"></div>
                <div class="manual-entry">
                    <p><strong>Manual entry:</strong></p>
                    <code>${this.formatSecret(response.secret)}</code>
                </div>
            </div>
        `;

        showModal('Setup Authenticator App', modalContent, [
            {
                text: 'Done',
                type: 'btn-primary',
                onclick: () => closeModal()
            }
        ]);

        // Generate QR code in modal
        setTimeout(() => {
            const qrEl = document.getElementById('modal-qr-code');
            if (qrEl) {
                QRCode.toCanvas(qrEl, response.qrCodeUrl, {
                    width: 150,
                    height: 150,
                    margin: 1
                });
            }
        }, 100);
    }

    /**
     * Validate TOTP code format
     */
    isValidTOTPCode(code) {
        return /^\d{6}$/.test(code);
    }

    /**
     * Clean and format TOTP input
     */
    formatTOTPInput(input) {
        return input.replace(/\D/g, '').substring(0, 6);
    }
}

// Global TOTP manager instance
const totpManager = new TOTPManager();

// Export for global use
window.totpManager = totpManager;

// Auto-setup TOTP input formatting
document.addEventListener('DOMContentLoaded', () => {
    const totpInputs = document.querySelectorAll('input[type="text"][maxlength="6"]');
    
    totpInputs.forEach(input => {
        input.addEventListener('input', (e) => {
            e.target.value = totpManager.formatTOTPInput(e.target.value);
        });
        
        input.addEventListener('paste', (e) => {
            e.preventDefault();
            const pastedText = (e.clipboardData || window.clipboardData).getData('text');
            e.target.value = totpManager.formatTOTPInput(pastedText);
        });
    });
});
