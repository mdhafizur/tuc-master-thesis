// SQL injection pattern (Devign-style)
// CWE: CWE-89
// Severity: high
// Source: Devign Pattern (fallback)
// Vulnerable lines: [3]

// Devign-style vulnerability pattern
function queryUser(userId) {
    const query = "SELECT * FROM users WHERE id = " + userId;
    return database.execute(query);
}