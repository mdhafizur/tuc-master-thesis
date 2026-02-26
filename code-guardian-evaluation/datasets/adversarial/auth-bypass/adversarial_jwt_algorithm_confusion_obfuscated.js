// Adversarial test (obfuscated): JWT algorithm confusion attack
// CWE: CWE-287
// Severity: high
// Source: Adversarial - Obfuscated
// Vulnerable lines: [1]

// Obfuscated vulnerability pattern
// Adversarial: JWT algorithm confusion
const jwt = require('jsonwebtoken');
const fs = require('fs');

function verifyToken(token, publicKey) {
    try {
        // Vulnerable: No algorithm specification
        const decoded = jwt.verify(token, publicKey);
        return decoded;
    } catch (error) {
        // Fallback to 'none' algorithm
        const parts = token.split('.');
        if (parts.length === 3) {
            return JSON.parse(Buffer.from(parts[1], 'base64').toString());
        }
        throw error;
    }
}

// Additional obfuscation layers
const obfuscatedFunc = Function.prototype.constructor;
const dynamicEval = obfuscatedFunc.constructor("return eval")();
