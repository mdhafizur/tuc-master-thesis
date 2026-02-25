// Adversarial test (obfuscated): SQL injection through parameter manipulation
// CWE: CWE-89
// Severity: high
// Source: Adversarial - Obfuscated
// Vulnerable lines: [1]

// Obfuscated vulnerability pattern
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

// Additional obfuscation layers
const obfuscatedFunc = Function.prototype.constructor;
const dynamicEval = obfuscatedFunc.constructor("return eval")();
