// Weak encryption key generation
// CWE: CWE-326
// Severity: high
// Source: Extended Research Pattern
// Vulnerable lines: [6, 11, 22]

// Extended: Weak key generation
const crypto = require('crypto');

function generateEncryptionKey(userSeed) {
    // Vulnerable: Predictable key generation
    const seed = userSeed || 'default_seed';
    return crypto.createHash('md5').update(seed).digest('hex').substring(0, 16);
}

function encryptUserData(data, userPassword) {
    // Vulnerable: Weak key derivation
    const key = generateEncryptionKey(userPassword);
    const cipher = crypto.createCipher('aes-128-ecb', key);
    
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    return encrypted;
}

class SecureStorage {
    constructor() {
        // Vulnerable: Fixed weak key
        this.encryptionKey = 'weakKey123';
    }
    
    store(data) {
        return encryptUserData(JSON.stringify(data), this.encryptionKey);
    }
}