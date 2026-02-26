// Adversarial test: Cryptographic timing attack
// CWE: CWE-208
// Severity: high
// Source: Adversarial - Original Pattern
// Vulnerable lines: [1]

// Adversarial: Timing attack vulnerability
function verifyApiKey(providedKey, validKey) {
    if (providedKey.length !== validKey.length) {
        return false;
    }
    
    // Vulnerable: Early termination allows timing attacks
    for (let i = 0; i < providedKey.length; i++) {
        if (providedKey[i] !== validKey[i]) {
            return false; // Timing leak here
        }
    }
    
    return true;
}