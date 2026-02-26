// Adversarial test: Nested prototype pollution
// CWE: CWE-1321
// Severity: high
// Source: Adversarial - Original Pattern
// Vulnerable lines: [1]

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