// Hardcoded database credentials
// CWE: CWE-798
// Severity: high
// Source: Additional Benchmark Pattern
// Vulnerable lines: [9, 17]

// Additional benchmark: Hardcoded credentials
const mysql = require('mysql');

function createDatabaseConnection() {
    // Vulnerable: Hardcoded credentials
    const connection = mysql.createConnection({
        host: 'localhost',
        user: 'admin',
        password: 'SuperSecret123!',
        database: 'production_db'
    });
    
    return connection;
}

const dbConfig = {
    // Vulnerable: Another hardcoded credential
    apiKey: 'sk-1234567890abcdef',
    secretKey: 'secret_key_hardcoded_here'
};