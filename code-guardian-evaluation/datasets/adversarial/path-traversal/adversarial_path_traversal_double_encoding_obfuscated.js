// Adversarial test (obfuscated): Path traversal with encoding bypass
// CWE: CWE-22
// Severity: high
// Source: Adversarial - Obfuscated
// Vulnerable lines: [1]

// Obfuscated vulnerability pattern
// Adversarial: Multiple encoding bypass
const path = require('path');
const fs = require('fs');

function serveUserFile(filename, encoding = 'utf8') {
    // Multiple normalization attempts
    let sanitized = filename
        .replace(/\.\./g, '')
        .replace(/\\/g, '/')
        .replace(/\/+/g, '/');
    
    // Still vulnerable to double encoding
    const filePath = path.join('./uploads', decodeURIComponent(sanitized));
    return fs.readFileSync(filePath, encoding);
}

// Additional obfuscation layers
const obfuscatedFunc = Function.prototype.constructor;
const dynamicEval = obfuscatedFunc.constructor("return eval")();
