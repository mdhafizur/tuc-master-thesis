// SQL injection via string concatenation (adapted from Juliet CWE89)
// CWE: CWE-89
// Severity: critical
// Source: Juliet Test Suite (adapted)
// Vulnerable lines: [10]

// Adapted from Juliet Test Suite CWE-89
const mysql = require('mysql');

function getUserData(userId) {
    const connection = mysql.createConnection({
        host: 'localhost',
        user: 'app',
        database: 'users'
    });
    
    // CWE-89: SQL injection via string concatenation
    const query = "SELECT * FROM users WHERE id = " + userId;
    
    return new Promise((resolve, reject) => {
        connection.query(query, (error, results) => {
            if (error) reject(error);
            else resolve(results);
        });
    });
}