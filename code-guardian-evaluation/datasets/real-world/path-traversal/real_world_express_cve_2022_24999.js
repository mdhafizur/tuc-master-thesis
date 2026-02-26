// Real CVE-2022-24999 vulnerability in express
// CWE: CWE-22
// Severity: high
// Source: express - CVE-2022-24999
// CVE: CVE-2022-24999
// Vulnerable lines: [8, 9]

// Real CVE-2022-24999 in Express.js
const path = require('path');
const fs = require('fs');

// Vulnerable implementation from Express
function sendFile(req, res, options) {
    const filePath = req.params.path;
    const root = options.root || './public';
    
    // VULNERABILITY: Insufficient path traversal protection
    const fullPath = path.resolve(root, filePath);
    
    if (fs.existsSync(fullPath)) {
        res.sendFile(fullPath);
    } else {
        res.status(404).send('File not found');
    }
}

// Attack: GET /files/../../../../etc/passwd