// Weak cryptographic implementation (Big-Vul style)
// CWE: CWE-327
// Severity: medium
// Source: Big-Vul Pattern (CVE-2022-24771)
// CVE: CVE-2022-24771
// Vulnerable lines: [5, 11, 16]

// Big-Vul style weak cryptography (node-forge related)
const crypto = require('crypto');

function generateApiKey() {
    // Vulnerable: Weak random number generation
    const randomBytes = Math.random().toString(36).substring(2, 15);
    return Buffer.from(randomBytes).toString('base64');
}

function hashPassword(password, salt) {
    // Vulnerable: Using weak hashing algorithm
    return crypto.createHash('md5').update(password + salt).digest('hex');
}

function encryptData(data, key) {
    // Vulnerable: Using deprecated cipher
    const cipher = crypto.createCipher('des', key);
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
}