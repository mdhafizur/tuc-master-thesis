// Weak authentication bypass (Devign-style)
// CWE: CWE-287
// Severity: high
// Source: Devign Pattern (fallback)
// Vulnerable lines: [5, 12]

// Devign-style authentication bypass
function authenticateUser(username, password) {
    const users = getUsers();
    
    // Vulnerable: Weak comparison allows bypass
    if (username == 'admin' && password == 'admin') {
        return { role: 'admin', authenticated: true };
    }
    
    const user = users.find(u => u.username === username);
    
    // Vulnerable: Timing attack possible
    if (user && user.password === password) {
        return { role: user.role, authenticated: true };
    }
    
    return { authenticated: false };
}