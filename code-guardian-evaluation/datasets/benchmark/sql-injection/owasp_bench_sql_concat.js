// SQL injection via string concatenation (OWASP Benchmark)
// CWE: CWE-89
// Severity: critical
// Source: OWASP Benchmark SQL-01
// Vulnerable lines: [7]

// OWASP Benchmark: SQL injection via concatenation
const sqlite3 = require('sqlite3').verbose();

function searchProducts(searchTerm) {
    const db = new sqlite3.Database('products.db');
    
    // Vulnerable: Direct string concatenation
    const query = "SELECT * FROM products WHERE name LIKE '%" + searchTerm + "%'";
    
    return new Promise((resolve, reject) => {
        db.all(query, [], (err, rows) => {
            if (err) reject(err);
            else resolve(rows);
        });
    });
}