// Adversarial test: Command injection through template processing
// CWE: CWE-78
// Severity: high
// Source: Adversarial - Original Pattern
// Vulnerable lines: [2, 9, 16]

// Adversarial: Template-based command injection
const { exec } = require('child_process');

function processTemplate(template, data) {
    // Template processing with command execution
    const processed = template.replace(/\\{\\{([^}]+)\\}\\}/g, (match, expr) => {
        try {
            // Dangerous evaluation
            return Function('"use strict"; return (' + expr + ')')();
        } catch {
            return match;
        }
    });
    
    if (data.executeCommand) {
        exec(`echo "${processed}" > output.txt`);
    }
    
    return processed;
}