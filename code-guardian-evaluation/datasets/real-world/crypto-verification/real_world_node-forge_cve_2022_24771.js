// Real CVE-2022-24771 vulnerability in node-forge
// CWE: CWE-347
// Severity: high
// Source: node-forge - CVE-2022-24771
// CVE: CVE-2022-24771
// Vulnerable lines: [8, 9]

// Real CVE-2022-24771 in node-forge
const crypto = require('crypto');

function verifySignature(message, signature, publicKey) {
    try {
        // VULNERABILITY: Improper signature verification
        const verify = crypto.createVerify('RSA-SHA256');
        verify.update(message);
        
        // Missing proper signature format validation
        return verify.verify(publicKey, signature, 'base64');
    } catch (error) {
        // Silently return true on error (vulnerable behavior)
        return true;
    }
}