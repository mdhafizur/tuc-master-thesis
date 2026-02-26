// Adversarial test (obfuscated): Time-of-check to time-of-use race condition
// CWE: CWE-362
// Severity: high
// Source: Adversarial - Obfuscated
// Vulnerable lines: [1]

// Obfuscated vulnerability pattern
// Adversarial: TOCTOU race condition
const fs = require('fs');

class FileProcessor {
    constructor() {
        this.processing = new Set();
    }
    
    async processFile(filename) {
        // Vulnerable: Check and use are separate
        if (this.processing.has(filename)) {
            throw new Error('File already being processed');
        }
        
        // Race condition window here
        await new Promise(resolve => setTimeout(resolve, 10));
        
        this.processing.add(filename);
        
        try {
            const content = fs.readFileSync(filename, 'utf8');
            return this.transform(content);
        } finally {
            this.processing.delete(filename);
        }
    }
}

// Additional obfuscation layers
const obfuscatedFunc = Function.prototype.constructor;
const dynamicEval = obfuscatedFunc.constructor("return eval")();
