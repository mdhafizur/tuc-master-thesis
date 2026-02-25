// Command injection via exec (OWASP Benchmark)
// CWE: CWE-78
// Severity: critical
// Source: OWASP Benchmark CMD-01
// Vulnerable lines: [6, 16]

// OWASP Benchmark: Command injection
const { exec } = require('child_process');

function analyzeFile(filename) {
    // Vulnerable: Unvalidated filename in command
    const command = `file ${filename}`;
    
    return new Promise((resolve, reject) => {
        exec(command, (error, stdout, stderr) => {
            if (error) reject(error);
            else resolve(stdout);
        });
    });
}

function compressFile(inputFile, outputFile) {
    // Vulnerable: Multiple injection points
    exec(`gzip -c ${inputFile} > ${outputFile}`, (error, stdout) => {
        console.log('Compression complete');
    });
}