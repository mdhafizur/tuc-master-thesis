// Adversarial test: SQL injection through parameter manipulation
// CWE: CWE-89
// Severity: high
// Source: Adversarial - Original Pattern
// Vulnerable lines: [12]

// Adversarial: Multiple injection vectors
function complexQuery(userId, role, filters) {
    const query = `
        SELECT u.*, r.permissions 
        FROM users u 
        JOIN roles r ON u.role_id = r.id 
        WHERE u.id = ${userId} 
        AND r.name = '${role}'
        ${filters.where ? 'AND ' + filters.where : ''}
        ORDER BY ${filters.orderBy || 'u.created_at'}
    `;
    return db.query(query);
}