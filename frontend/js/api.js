/**
 * OneID 2.0 API Client
 * Handles all communication with the OneID backend server
 */

class OneIDAPI {
    constructor() {
        this.baseURL = window.location.protocol + '//' + window.location.hostname + ':3000/api/v1';
        this.token = localStorage.getItem('oneID_token');
        this.refreshToken = localStorage.getItem('oneID_refresh_token');
    }

    // === AUTH ENDPOINTS ===

    /**
     * Register new user
     */
    async register(data) {
        const deviceFingerprint = await generateDeviceFingerprint();
        return this._makeRequest('/auth/register', 'POST', {
            ...data,
            deviceFingerprint
        });
    }

    /**
     * Login user
     */
    async login(identifier, password, trustDevice = false) {
        const deviceFingerprint = await generateDeviceFingerprint();
        return this._makeRequest('/auth/login', 'POST', {
            identifier,
            password,
            trustDevice,
            deviceFingerprint
        });
    }

    /**
     * Complete two-factor authentication
     */
    async completeTwoFactor(sessionId, code, method) {
        return this._makeRequest('/auth/complete-two-factor', 'POST', {
            sessionId,
            code,
            method
        });
    }

    /**
     * Refresh access token
     */
    async refreshAccessToken() {
        if (!this.refreshToken) {
            throw new Error('No refresh token available');
        }

        try {
            const response = await this._makeRequest('/auth/refresh', 'POST', {
                refreshToken: this.refreshToken
            }, false); // Don't use auth for refresh

            this.token = response.accessToken;
            this.refreshToken = response.refreshToken;
            localStorage.setItem('oneID_token', this.token);
            localStorage.setItem('oneID_refresh_token', this.refreshToken);

            return response;
        } catch (error) {
            // If refresh fails, clear tokens
            this.clearTokens();
            throw error;
        }
    }

    /**
     * Logout user
     */
    async logout() {
        try {
            await this._makeRequest('/auth/logout', 'POST');
        } finally {
            this.clearTokens();
        }
    }

    // === TOTP ENDPOINTS ===

    /**
     * Setup TOTP for user
     */
    async setupTOTP() {
        return this._makeRequest('/totp/setup', 'POST');
    }

    /**
     * Verify TOTP setup
     */
    async verifyTOTPSetup(secret, code) {
        return this._makeRequest('/totp/verify-setup', 'POST', {
            secret,
            code
        });
    }

    /**
     * Generate backup codes
     */
    async generateBackupCodes() {
        return this._makeRequest('/totp/backup-codes', 'POST');
    }

    /**
     * Regenerate TOTP secret
     */
    async regenerateTOTP() {
        return this._makeRequest('/totp/regenerate', 'POST');
    }

    /**
     * Disable TOTP
     */
    async disableTOTP(password) {
        return this._makeRequest('/totp/disable', 'POST', {
            password
        });
    }

    // === WEBAUTHN ENDPOINTS ===

    /**
     * Get WebAuthn registration options
     */
    async getWebAuthnRegistrationOptions() {
        return this._makeRequest('/webauthn/registration/options', 'GET');
    }

    /**
     * Complete WebAuthn registration
     */
    async completeWebAuthnRegistration(credential) {
        return this._makeRequest('/webauthn/registration/complete', 'POST', {
            credential
        });
    }

    /**
     * Get WebAuthn authentication options
     */
    async getWebAuthnAuthenticationOptions() {
        return this._makeRequest('/webauthn/authentication/options', 'GET');
    }

    /**
     * Complete WebAuthn authentication
     */
    async completeWebAuthnAuthentication(credential) {
        return this._makeRequest('/webauthn/authentication/complete', 'POST', {
            credential
        });
    }

    // === SECURITY ENDPOINTS ===

    /**
     * Get OneID Score
     */
    async getOneIDScore() {
        return this._makeRequest('/security/oneid-score', 'GET');
    }

    /**
     * Get security events
     */
    async getSecurityEvents(limit = 10, offset = 0) {
        return this._makeRequest(`/security/events?limit=${limit}&offset=${offset}`, 'GET');
    }

    /**
     * Report security incident
     */
    async reportSecurityIncident(type, description) {
        return this._makeRequest('/security/report', 'POST', {
            type,
            description
        });
    }

    // === DEVICE ENDPOINTS ===

    /**
     * Register device
     */
    async registerDevice(name, type) {
        const fingerprint = await generateDeviceFingerprint();
        return this._makeRequest('/devices/register', 'POST', {
            name,
            type,
            fingerprint
        });
    }

    /**
     * Get user devices
     */
    async getDevices() {
        return this._makeRequest('/devices', 'GET');
    }

    /**
     * Revoke device
     */
    async revokeDevice(deviceId) {
        return this._makeRequest(`/devices/${deviceId}/revoke`, 'POST');
    }

    /**
     * Trust device
     */
    async trustDevice(deviceId) {
        return this._makeRequest(`/devices/${deviceId}/trust`, 'POST');
    }

    // === RECOVERY ENDPOINTS ===

    /**
     * Start account recovery
     */
    async startRecovery(identifier, method) {
        return this._makeRequest('/recovery/start', 'POST', {
            identifier,
            method
        });
    }

    /**
     * Complete recovery with email
     */
    async completeEmailRecovery(token, newPassword) {
        return this._makeRequest('/recovery/complete/email', 'POST', {
            token,
            newPassword
        });
    }

    /**
     * Complete recovery with secret phrase
     */
    async completeSecretPhraseRecovery(identifier, secretPhrase, newPassword) {
        return this._makeRequest('/recovery/complete/secret-phrase', 'POST', {
            identifier,
            secretPhrase,
            newPassword
        });
    }

    /**
     * Add trusted contact
     */
    async addTrustedContact(email, name) {
        return this._makeRequest('/recovery/trusted-contacts', 'POST', {
            email,
            name
        });
    }

    /**
     * Get trusted contacts
     */
    async getTrustedContacts() {
        return this._makeRequest('/recovery/trusted-contacts', 'GET');
    }

    // === USER ENDPOINTS ===

    /**
     * Get user profile
     */
    async getUserProfile() {
        return this._makeRequest('/users/profile', 'GET');
    }

    /**
     * Update user profile
     */
    async updateUserProfile(data) {
        return this._makeRequest('/users/profile', 'PUT', data);
    }

    /**
     * Change password
     */
    async changePassword(currentPassword, newPassword) {
        return this._makeRequest('/users/change-password', 'POST', {
            currentPassword,
            newPassword
        });
    }

    /**
     * Delete account
     */
    async deleteAccount(password, reason) {
        return this._makeRequest('/users/delete', 'POST', {
            password,
            reason
        });
    }

    // === PRIVATE METHODS ===

    /**
     * Make HTTP request to API
     */
    async _makeRequest(endpoint, method = 'GET', data = null, useAuth = true) {
        const url = this.baseURL + endpoint;
        const options = {
            method,
            headers: {
                'Content-Type': 'application/json',
                'X-Client-Version': '2.0.0',
                'X-Device-Fingerprint': await generateDeviceFingerprint()
            }
        };

        // Add authentication header
        if (useAuth && this.token) {
            options.headers['Authorization'] = `Bearer ${this.token}`;
        }

        // Add request body
        if (data) {
            options.body = JSON.stringify(data);
        }

        try {
            const response = await fetch(url, options);
            
            // Handle different response types
            if (response.status === 204) {
                return null; // No content
            }

            const responseData = await response.json();

            if (!response.ok) {
                // Handle token expiration
                if (response.status === 401 && useAuth && this.refreshToken) {
                    try {
                        await this.refreshAccessToken();
                        // Retry the original request
                        options.headers['Authorization'] = `Bearer ${this.token}`;
                        const retryResponse = await fetch(url, options);
                        if (retryResponse.ok) {
                            return retryResponse.status === 204 ? null : await retryResponse.json();
                        }
                    } catch (refreshError) {
                        // Refresh failed, clear tokens and redirect to login
                        this.clearTokens();
                        showScreen('welcome-screen');
                        throw new APIError('Session expired. Please login again.', 401);
                    }
                }

                throw new APIError(
                    responseData.message || 'Request failed',
                    response.status,
                    responseData
                );
            }

            return responseData;

        } catch (error) {
            if (error instanceof APIError) {
                throw error;
            }

            // Handle network errors
            if (error.name === 'TypeError' && error.message.includes('fetch')) {
                throw new APIError('Network error. Please check your connection.', 0);
            }

            throw new APIError(error.message || 'Unknown error occurred', 500);
        }
    }

    /**
     * Clear stored tokens
     */
    clearTokens() {
        this.token = null;
        this.refreshToken = null;
        localStorage.removeItem('oneID_token');
        localStorage.removeItem('oneID_refresh_token');
    }

    /**
     * Check if user is authenticated
     */
    isAuthenticated() {
        return !!this.token;
    }

    /**
     * Set authentication tokens
     */
    setTokens(accessToken, refreshToken) {
        this.token = accessToken;
        this.refreshToken = refreshToken;
        localStorage.setItem('oneID_token', accessToken);
        localStorage.setItem('oneID_refresh_token', refreshToken);
    }
}

/**
 * Custom API Error class
 */
class APIError extends Error {
    constructor(message, status, details = null) {
        super(message);
        this.name = 'APIError';
        this.status = status;
        this.details = details;
    }
}

// Global API instance
const oneIdAPI = new OneIDAPI();

// Export for use in other modules
window.oneIdAPI = oneIdAPI;
window.APIError = APIError;
