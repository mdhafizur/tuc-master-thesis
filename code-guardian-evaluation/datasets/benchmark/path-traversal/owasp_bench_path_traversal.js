// Path traversal in file serving (OWASP Benchmark)
// CWE: CWE-22
// Severity: high
// Source: OWASP Benchmark PATH-01
// Vulnerable lines: [9, 20]

// OWASP Benchmark: Path traversal
const fs = require('fs');
const express = require('express');
const app = express();

app.get('/files/:filename', (req, res) => {
    const filename = req.params.filename;
    
    // Vulnerable: No path validation
    const filepath = './uploads/' + filename;
    
    try {
        const content = fs.readFileSync(filepath, 'utf8');
        res.send(content);
    } catch (error) {
        res.status(404).send('File not found');
    }
});

function readConfigFile(configName) {
    // Vulnerable: Path traversal in config reading
    const configPath = './config/' + configName + '.json';
    return JSON.parse(fs.readFileSync(configPath, 'utf8'));
}