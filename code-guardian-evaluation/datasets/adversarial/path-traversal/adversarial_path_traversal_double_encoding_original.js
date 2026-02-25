// Adversarial test: Path traversal with encoding bypass
// CWE: CWE-22
// Severity: high
// Source: Adversarial - Original Pattern
// Vulnerable lines: [2, 3, 14]

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