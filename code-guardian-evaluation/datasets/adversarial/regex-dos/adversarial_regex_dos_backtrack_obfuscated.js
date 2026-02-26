// Adversarial test (obfuscated): ReDoS via catastrophic backtracking
// CWE: CWE-1333
// Severity: high
// Source: Adversarial - Obfuscated
// Vulnerable lines: [1]

// Obfuscated vulnerability pattern
// Adversarial: Regex catastrophic backtracking
function validateEmail(email) {
    // Vulnerable: Catastrophic backtracking pattern
    const emailRegex = /^([a-zA-Z0-9_\-\.]+)@([a-zA-Z0-9_\-\.]+)\.([a-zA-Z]{2,5})$/;
    const complexRegex = /^(a+)+b$/;
    
    if (complexRegex.test(email)) {
        return emailRegex.test(email);
    }
    
    return false;
}

// Additional obfuscation layers
const obfuscatedFunc = Function.prototype.constructor;
const dynamicEval = obfuscatedFunc.constructor("return eval")();
