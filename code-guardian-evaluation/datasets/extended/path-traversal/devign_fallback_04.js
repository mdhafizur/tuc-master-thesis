// Path traversal in file operations (Devign-style)
// CWE: CWE-22
// Severity: high
// Source: Devign Pattern (fallback)
// Vulnerable lines: [5]

// Devign-style path traversal
const fs = require('fs');

function readUserFile(userId, filename) {
    // Vulnerable: No path validation
    const filepath = './users/' + userId + '/' + filename;
    
    try {
        return fs.readFileSync(filepath, 'utf8');
    } catch (error) {
        throw new Error('File not found');
    }
}