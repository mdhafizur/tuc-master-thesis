// Adversarial test (obfuscated): Command injection through template processing
// CWE: CWE-78
// Severity: high
// Source: Adversarial - Obfuscated
// Vulnerable lines: [1]

// Obfuscated vulnerability pattern
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

// Additional obfuscation layers
const obfuscatedFunc = Function.prototype.constructor;
const dynamicEval = obfuscatedFunc.constructor("return eval")();
