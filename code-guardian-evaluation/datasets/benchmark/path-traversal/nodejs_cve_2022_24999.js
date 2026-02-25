// Path traversal in express static file serving
// CWE: CWE-22
// Severity: high
// Source: CVE-2022-24999
// CVE: CVE-2022-24999
// Vulnerable lines: [10]

// CVE-2022-24999: Path traversal in express static
const express = require('express');
const path = require('path');
const fs = require('fs');

const app = express();

// Vulnerable static file serving implementation
app.get('/files/:filename', (req, res) => {
    const filename = req.params.filename;
    const filePath = path.join(__dirname, 'public', filename);
    
    // Vulnerable: No validation of path traversal
    if (fs.existsSync(filePath)) {
        res.sendFile(filePath);
    } else {
        res.status(404).send('File not found');
    }
});

// Attack example: GET /files/../../../etc/passwd