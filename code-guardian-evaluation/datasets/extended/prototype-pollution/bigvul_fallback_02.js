// Prototype pollution vulnerability (Big-Vul style)
// CWE: CWE-1321
// Severity: high
// Source: Big-Vul Pattern (CVE-2020-8203)
// CVE: CVE-2020-8203
// Vulnerable lines: [7, 22]

// Big-Vul style prototype pollution (based on lodash CVE-2020-8203)
function merge(target, source) {
    for (let key in source) {
        if (typeof source[key] === 'object' && source[key] !== null) {
            if (!target[key]) target[key] = {};
            
            // Vulnerable: No protection against __proto__
            merge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

function setPath(object, path, value) {
    const keys = path.split('.');
    let current = object;
    
    for (let i = 0; i < keys.length - 1; i++) {
        const key = keys[i];
        if (!current[key]) current[key] = {};
        current = current[key];
    }
    
    // Vulnerable: No validation of key
    current[keys[keys.length - 1]] = value;
}