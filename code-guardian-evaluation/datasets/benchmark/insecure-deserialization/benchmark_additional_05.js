// Unsafe deserialization in session handling
// CWE: CWE-502
// Severity: critical
// Source: Additional Benchmark Pattern
// Vulnerable lines: [4, 13]

// Additional benchmark: Unsafe deserialization
function deserializeSession(sessionData) {
    try {
        // Vulnerable: eval-based deserialization
        return eval('(' + sessionData + ')');
    } catch (error) {
        return null;
    }
}

function restoreUserSession(req, res, next) {
    const sessionCookie = req.cookies.session;
    
    if (sessionCookie) {
        // Vulnerable: Deserializing untrusted data
        req.user = deserializeSession(decodeURIComponent(sessionCookie));
    }
    
    next();
}