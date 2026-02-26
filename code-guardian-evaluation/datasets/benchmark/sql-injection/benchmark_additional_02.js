// SQL injection in ORDER BY clause
// CWE: CWE-89
// Severity: high
// Source: Additional Benchmark Pattern
// Vulnerable lines: [7]

// Additional benchmark: SQL injection in ORDER BY
const mysql = require('mysql');

function getUsers(sortBy, sortOrder) {
    const connection = mysql.createConnection(dbConfig);
    
    // Vulnerable: Unvalidated ORDER BY parameters
    const query = `SELECT * FROM users ORDER BY ${sortBy} ${sortOrder}`;
    
    return new Promise((resolve, reject) => {
        connection.query(query, (error, results) => {
            if (error) reject(error);
            else resolve(results);
        });
    });
}