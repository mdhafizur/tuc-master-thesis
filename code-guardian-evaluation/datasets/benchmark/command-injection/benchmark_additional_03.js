// Command injection via file processing
// CWE: CWE-78
// Severity: critical
// Source: Additional Benchmark Pattern
// Vulnerable lines: [6]

// Additional benchmark: Command injection
const { spawn } = require('child_process');

function convertImage(inputFile, outputFormat) {
    // Vulnerable: Unvalidated file parameters
    const args = ['-format', outputFormat, inputFile, `output.${outputFormat}`];
    
    const convert = spawn('convert', args);
    
    convert.on('error', (error) => {
        console.error('Conversion failed:', error);
    });
    
    return convert;
}