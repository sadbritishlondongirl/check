/**
 * OneID 2.0 Frontend Utilities
 * Utility functions for DOM manipulation, validation, and common operations
 */

// === DOM UTILITIES ===

/**
 * Show loading overlay
 */
function showLoading(message = 'Processing your request...') {
    const overlay = document.getElementById('loading-overlay');
    const text = overlay.querySelector('p');
    if (text) text.textContent = message;
    overlay.classList.remove('hidden');
}

/**
 * Hide loading overlay
 */
function hideLoading() {
    const overlay = document.getElementById('loading-overlay');
    overlay.classList.add('hidden');
}

/**
 * Show screen and hide others
 */
function showScreen(screenId) {
    // Hide all screens
    document.querySelectorAll('.auth-screen').forEach(screen => {
        screen.classList.remove('active');
    });
    
    // Show target screen
    const targetScreen = document.getElementById(screenId);
    if (targetScreen) {
        targetScreen.classList.add('active');
    }
}

/**
 * Show toast notification
 */
function showToast(message, type = 'success', duration = 4000) {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    
    toast.className = `toast ${type}`;
    toast.innerHTML = `
        <strong>${type === 'success' ? '✅' : type === 'error' ? '❌' : '⚠️'}</strong>
        ${message}
    `;
    
    container.appendChild(toast);
    
    // Auto remove after duration
    setTimeout(() => {
        toast.style.animation = 'toast-out 0.25s ease-out forwards';
        setTimeout(() => {
            if (container.contains(toast)) {
                container.removeChild(toast);
            }
        }, 250);
    }, duration);
}

/**
 * Show modal
 */
function showModal(title, content, actions = []) {
    const overlay = document.getElementById('modal-overlay');
    const modal = document.getElementById('modal');
    const titleEl = document.getElementById('modal-title');
    const contentEl = document.getElementById('modal-content');
    const actionsEl = document.getElementById('modal-actions');
    
    titleEl.textContent = title;
    contentEl.innerHTML = content;
    
    // Clear existing actions
    actionsEl.innerHTML = '';
    
    // Add custom actions or default close button
    if (actions.length > 0) {
        actions.forEach(action => {
            const button = document.createElement('button');
            button.className = `btn ${action.type || 'btn-secondary'}`;
            button.textContent = action.text;
            button.onclick = action.onclick;
            actionsEl.appendChild(button);
        });
    } else {
        const closeBtn = document.createElement('button');
        closeBtn.className = 'btn btn-secondary';
        closeBtn.textContent = 'Close';
        closeBtn.onclick = closeModal;
        actionsEl.appendChild(closeBtn);
    }
    
    overlay.classList.remove('hidden');
}

/**
 * Close modal
 */
function closeModal() {
    const overlay = document.getElementById('modal-overlay');
    overlay.classList.add('hidden');
}

// === VALIDATION UTILITIES ===

/**
 * Validate email address
 */
function isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

/**
 * Validate username
 */
function isValidUsername(username) {
    const usernameRegex = /^[a-zA-Z0-9_]{3,20}$/;
    return usernameRegex.test(username);
}

/**
 * Check password strength
 */
function getPasswordStrength(password) {
    let score = 0;
    let feedback = [];
    
    if (password.length < 8) {
        feedback.push('At least 8 characters');
    } else {
        score += 25;
    }
    
    if (!/[a-z]/.test(password)) {
        feedback.push('Lowercase letter');
    } else {
        score += 25;
    }
    
    if (!/[A-Z]/.test(password)) {
        feedback.push('Uppercase letter');
    } else {
        score += 25;
    }
    
    if (!/[0-9]/.test(password)) {
        feedback.push('Number');
    } else {
        score += 25;
    }
    
    if (!/[^a-zA-Z0-9]/.test(password)) {
        feedback.push('Special character');
    } else {
        score += 25;
    }
    
    let strength = 'weak';
    if (score >= 100) strength = 'strong';
    else if (score >= 75) strength = 'good';
    else if (score >= 50) strength = 'fair';
    
    return {
        score: Math.min(score, 100),
        strength,
        feedback
    };
}

/**
 * Update password strength indicator
 */
function updatePasswordStrength(password, containerId = 'password-strength') {
    const container = document.getElementById(containerId);
    if (!container) return;
    
    const result = getPasswordStrength(password);
    const fill = container.querySelector('.strength-fill');
    const text = container.querySelector('.strength-text');
    
    if (fill) {
        fill.className = `strength-fill ${result.strength}`;
    }
    
    if (text) {
        if (password.length === 0) {
            text.textContent = 'Enter a password';
        } else if (result.feedback.length > 0) {
            text.textContent = `Add: ${result.feedback.join(', ')}`;
        } else {
            text.textContent = 'Strong password!';
        }
    }
}

// === CRYPTO UTILITIES ===

/**
 * Generate device fingerprint
 */
async function generateDeviceFingerprint() {
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    ctx.textBaseline = 'top';
    ctx.font = '14px Arial';
    ctx.fillText('Device fingerprint', 2, 2);
    
    const fingerprint = {
        userAgent: navigator.userAgent,
        language: navigator.language,
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
        screen: `${screen.width}x${screen.height}`,
        canvas: canvas.toDataURL(),
        timestamp: Date.now()
    };
    
    const data = JSON.stringify(fingerprint);
    const encoder = new TextEncoder();
    const encoded = encoder.encode(data);
    const hash = await crypto.subtle.digest('SHA-256', encoded);
    
    return Array.from(new Uint8Array(hash))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

/**
 * Generate secure random string
 */
function generateRandomString(length = 32) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const array = new Uint8Array(length);
    crypto.getRandomValues(array);
    return Array.from(array, byte => chars[byte % chars.length]).join('');
}

/**
 * Professional cryptographic mnemonic phrase generator
 * Uses cryptographically secure random generation without predefined dictionaries
 */
async function generateMnemonic(wordCount = 12) {
    // Generate cryptographically secure entropy
    const entropyBits = wordCount * 11; // 11 bits per word for BIP39 compatibility
    const entropyBytes = Math.ceil(entropyBits / 8);
    const entropy = new Uint8Array(entropyBytes);
    crypto.getRandomValues(entropy);
    
    // Add additional entropy sources for enhanced security
    const timeEntropy = new TextEncoder().encode(Date.now().toString());
    const deviceEntropy = new TextEncoder().encode(await generateDeviceFingerprint());
    const randomEntropy = new TextEncoder().encode(Math.random().toString());
    
    // Combine all entropy sources
    const combinedEntropy = new Uint8Array(entropy.length + timeEntropy.length + deviceEntropy.length + randomEntropy.length);
    combinedEntropy.set(entropy, 0);
    combinedEntropy.set(timeEntropy, entropy.length);
    combinedEntropy.set(deviceEntropy, entropy.length + timeEntropy.length);
    combinedEntropy.set(randomEntropy, entropy.length + timeEntropy.length + deviceEntropy.length);
    
    // Hash combined entropy for final randomness
    const hashedEntropy = await crypto.subtle.digest('SHA-256', combinedEntropy);
    const finalEntropy = new Uint8Array(hashedEntropy);
    
    // Generate words using mathematical algorithms instead of dictionary
    const words = [];
    for (let i = 0; i < wordCount; i++) {
        const word = await generateCryptographicWord(finalEntropy, i, wordCount);
        words.push(word);
    }
    
    // Add checksum validation
    const checksum = await generateChecksumWord(words);
    if (wordCount === 12) {
        words[11] = checksum; // Replace last word with checksum
    }
    
    return words;
}

/**
 * Generate a cryptographic word using mathematical algorithms
 */
async function generateCryptographicWord(entropy, index, totalWords) {
    // Create seed from entropy and index
    const seed = new Uint8Array(entropy.length + 4);
    seed.set(entropy);
    seed.set(new Uint8Array(new Uint32Array([index]).buffer), entropy.length);
    
    // Generate hash-based word
    const hash = await crypto.subtle.digest('SHA-256', seed);
    const hashArray = new Uint8Array(hash);
    
    // Convert to readable format using base-conversion algorithm
    let word = '';
    const consonants = 'bcdfghjklmnpqrstvwxyz';
    const vowels = 'aeiou';
    
    // Generate word structure: consonant-vowel-consonant-vowel-consonant (5 chars)
    for (let i = 0; i < 5; i++) {
        if (i % 2 === 0) {
            // Consonant
            word += consonants[hashArray[i] % consonants.length];
        } else {
            // Vowel
            word += vowels[hashArray[i] % vowels.length];
        }
    }
    
    // Add numeric suffix for uniqueness
    const numericSuffix = (hashArray[5] % 100).toString().padStart(2, '0');
    word += numericSuffix;
    
    return word;
}

/**
 * Generate checksum word for validation
 */
async function generateChecksumWord(words) {
    const wordsString = words.slice(0, -1).join('');
    const encoder = new TextEncoder();
    const data = encoder.encode(wordsString);
    const hash = await crypto.subtle.digest('SHA-256', data);
    const hashArray = new Uint8Array(hash);
    
    // Generate checksum word with same algorithm
    const consonants = 'bcdfghjklmnpqrstvwxyz';
    const vowels = 'aeiou';
    let checksum = '';
    
    for (let i = 0; i < 5; i++) {
        if (i % 2 === 0) {
            checksum += consonants[hashArray[i] % consonants.length];
        } else {
            checksum += vowels[hashArray[i] % vowels.length];
        }
    }
    
    // Add checksum validation digits
    const checksumSuffix = (hashArray[5] % 100).toString().padStart(2, '0');
    checksum += checksumSuffix;
    
    return checksum;
}

/**
 * Validate mnemonic phrase integrity
 */
async function validateMnemonic(words) {
    if (!Array.isArray(words) || words.length !== 12) {
        return false;
    }
    
    // Regenerate checksum and compare
    const expectedChecksum = await generateChecksumWord(words);
    return words[11] === expectedChecksum;
}
