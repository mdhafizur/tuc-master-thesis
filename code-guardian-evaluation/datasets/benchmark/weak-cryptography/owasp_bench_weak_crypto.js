// Weak cryptographic algorithms (OWASP Benchmark)
// CWE: CWE-327
// Severity: medium
// Source: OWASP Benchmark CRYPTO-01
// Vulnerable lines: [5, 10, 17]

// OWASP Benchmark: Weak cryptography
const crypto = require('crypto');

function hashPassword(password) {
    // Vulnerable: Using weak MD5 algorithm
    return crypto.createHash('md5').update(password).digest('hex');
}

function encryptData(data, key) {
    // Vulnerable: Using DES encryption
    const cipher = crypto.createCipher('des', key);
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
}

function generateToken() {
    // Vulnerable: Weak random number generation
    return Math.random().toString(36).substring(2, 15);
}