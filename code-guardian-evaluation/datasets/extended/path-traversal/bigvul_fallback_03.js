// Express.js path traversal (Big-Vul style)
// CWE: CWE-22
// Severity: high
// Source: Big-Vul Pattern (CVE-2022-24999)
// CVE: CVE-2022-24999
// Vulnerable lines: [11]

// Big-Vul style Express.js path traversal
const express = require('express');
const path = require('path');
const fs = require('fs');

const app = express();

app.get('/static/:file', (req, res) => {
    const filename = req.params.file;
    
    // Vulnerable: No path validation (CVE-2022-24999 style)
    const filePath = path.join('./static', filename);
    
    fs.readFile(filePath, (err, data) => {
        if (err) {
            res.status(404).send('File not found');
        } else {
            res.send(data);
        }
    });
});