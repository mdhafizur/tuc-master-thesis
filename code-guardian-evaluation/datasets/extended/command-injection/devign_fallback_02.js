// Command injection vulnerability (Devign-style)
// CWE: CWE-78
// Severity: critical
// Source: Devign Pattern (fallback)
// Vulnerable lines: [6]

// Devign-style command injection
const { exec } = require('child_process');

function processFile(filename) {
    // Vulnerable: Command injection
    const command = `file ${filename}`;
    exec(command, (error, stdout, stderr) => {
        console.log(stdout);
    });
}