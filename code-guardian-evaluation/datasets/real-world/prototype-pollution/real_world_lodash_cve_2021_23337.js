// Real CVE-2021-23337 vulnerability in lodash
// CWE: CWE-1321
// Severity: high
// Source: lodash - CVE-2021-23337
// CVE: CVE-2021-23337
// Vulnerable lines: [8, 9]

// Real CVE-2021-23337 in Lodash
function merge(object, sources) {
    // Simplified version of vulnerable lodash merge
    sources.forEach(source => {
        for (let key in source) {
            if (source.hasOwnProperty(key)) {
                // VULNERABILITY: No protection against __proto__ pollution
                if (typeof source[key] === 'object' && typeof object[key] === 'object') {
                    merge(object[key], [source[key]]);
                } else {
                    object[key] = source[key];
                }
            }
        }
    });
    return object;
}

// Attack payload: {"__proto__": {"polluted": true}}