// Adversarial test (obfuscated): Nested prototype pollution
// CWE: CWE-1321
// Severity: high
// Source: Adversarial - Obfuscated
// Vulnerable lines: [1]

// Obfuscated vulnerability pattern
// Adversarial: Deep nested pollution
function deepMergeConfig(target, source, depth = 0) {
    if (depth > 10) return target; // Recursion limit
    
    for (const key in source) {
        if (source[key] && typeof source[key] === 'object') {
            if (!target[key]) target[key] = {};
            deepMergeConfig(target[key], source[key], depth + 1);
        } else {
            target[key] = source[key]; // Pollution vector
        }
    }
    return target;
}

// Additional obfuscation layers
const obfuscatedFunc = Function.prototype.constructor;
const dynamicEval = obfuscatedFunc.constructor("return eval")();
