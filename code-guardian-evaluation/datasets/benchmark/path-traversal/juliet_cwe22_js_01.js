// Path traversal via file access (adapted from Juliet CWE22)
// CWE: CWE-22
// Severity: high
// Source: Juliet Test Suite (adapted)
// Vulnerable lines: [8]

// Adapted from Juliet Test Suite CWE-22
const fs = require('fs');
const path = require('path');

function readUserFile(fileName) {
    const baseDir = '/app/user-files/';
    
    // CWE-22: Path traversal via unvalidated file path
    const filePath = baseDir + fileName;
    
    try {
        const content = fs.readFileSync(filePath, 'utf8');
        return content;
    } catch (error) {
        throw new Error('File not found');
    }
}

// Usage that enables path traversal
function getFileContent(userProvidedPath) {
    return readUserFile(userProvidedPath);
}