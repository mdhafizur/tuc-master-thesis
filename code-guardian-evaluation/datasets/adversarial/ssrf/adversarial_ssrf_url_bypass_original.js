// Adversarial test: SSRF with URL validation bypass
// CWE: CWE-918
// Severity: high
// Source: Adversarial - Original Pattern
// Vulnerable lines: [2, 3]

// Adversarial: SSRF URL bypass techniques
const http = require('http');
const url = require('url');

function fetchResource(resourceUrl) {
    const parsed = url.parse(resourceUrl);
    
    // Vulnerable: Insufficient blacklist
    const blockedHosts = ['localhost', '127.0.0.1', '0.0.0.0'];
    
    if (blockedHosts.includes(parsed.hostname)) {
        throw new Error('Blocked host');
    }
    
    // Still vulnerable to bypass techniques
    return new Promise((resolve, reject) => {
        http.get(resourceUrl, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => resolve(data));
        }).on('error', reject);
    });
}