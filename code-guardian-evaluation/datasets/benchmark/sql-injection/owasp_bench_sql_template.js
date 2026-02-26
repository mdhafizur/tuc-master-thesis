// SQL injection via template literals (OWASP Benchmark)
// CWE: CWE-89
// Severity: critical
// Source: OWASP Benchmark SQL-02
// Vulnerable lines: [7]

// OWASP Benchmark: SQL injection via template literals
const mysql = require('mysql');

function loginUser(username, password) {
    const connection = mysql.createConnection(dbConfig);
    
    // Vulnerable: Template literal without escaping
    const sql = `SELECT id, role FROM users WHERE username='${username}' AND password='${password}'`;
    
    return new Promise((resolve, reject) => {
        connection.query(sql, (error, results) => {
            if (error) reject(error);
            resolve(results[0] || null);
        });
    });
}