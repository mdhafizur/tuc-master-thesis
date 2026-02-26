// Authentication bypass via parameter manipulation
// CWE: CWE-287
// Severity: critical
// Source: Additional Benchmark Pattern
// Vulnerable lines: [6, 19]

// Additional benchmark: Authentication bypass
function authenticateUser(username, password, isAdmin) {
    const users = getUserDatabase();
    const user = users.find(u => u.username === username);
    
    // Vulnerable: Client-controlled admin flag
    if (isAdmin === 'true') {
        return { authenticated: true, role: 'admin', user: user };
    }
    
    if (user && user.password === password) {
        return { authenticated: true, role: user.role, user: user };
    }
    
    return { authenticated: false };
}

function checkAdminAccess(req, res, next) {
    // Vulnerable: No proper authentication check
    if (req.query.admin === 'true') {
        req.user = { role: 'admin' };
    }
    next();
}