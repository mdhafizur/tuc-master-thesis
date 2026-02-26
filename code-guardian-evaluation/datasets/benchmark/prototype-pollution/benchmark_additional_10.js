// Prototype pollution via recursive merge
// CWE: CWE-1321
// Severity: high
// Source: Additional Benchmark Pattern
// Vulnerable lines: [8, 18]

// Additional benchmark: Prototype pollution
function recursiveMerge(target, source) {
    for (const key in source) {
        if (source.hasOwnProperty(key)) {
            if (typeof source[key] === 'object' && source[key] !== null) {
                if (!target[key]) target[key] = {};
                // Vulnerable: No __proto__ protection
                recursiveMerge(target[key], source[key]);
            } else {
                target[key] = source[key];
            }
        }
    }
    return target;
}

function updateConfig(userConfig) {
    const defaultConfig = { timeout: 5000, retries: 3 };
    // Vulnerable: Merging untrusted user input
    return recursiveMerge(defaultConfig, userConfig);
}