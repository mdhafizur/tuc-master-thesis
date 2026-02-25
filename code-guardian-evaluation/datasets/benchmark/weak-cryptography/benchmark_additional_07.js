// Weak cryptographic hash functions
// CWE: CWE-327
// Severity: medium
// Source: Additional Benchmark Pattern
// Vulnerable lines: [5, 10, 16]

// Additional benchmark: Weak cryptography
const crypto = require('crypto');

function hashUserPassword(password, salt) {
    // Vulnerable: Using SHA1 for password hashing
    return crypto.createHash('sha1').update(password + salt).digest('hex');
}

function generateSessionId() {
    // Vulnerable: Weak random generation
    return Math.random().toString(36).substring(2, 15) + 
           Math.random().toString(36).substring(2, 15);
}

function encryptSensitiveData(data, key) {
    // Vulnerable: Using RC4 cipher
    const cipher = crypto.createCipher('rc4', key);
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
}