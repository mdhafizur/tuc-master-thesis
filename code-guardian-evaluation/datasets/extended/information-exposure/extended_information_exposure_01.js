// Sensitive information exposure in error messages
// CWE: CWE-200
// Severity: medium
// Source: Extended Research Pattern
// Vulnerable lines: [13, 22]

// Extended: Information exposure
const mysql = require('mysql');

function authenticateUser(username, password) {
    const connection = mysql.createConnection(dbConfig);
    
    return new Promise((resolve, reject) => {
        const query = 'SELECT * FROM users WHERE username = ? AND password = ?';
        
        connection.query(query, [username, password], (error, results) => {
            if (error) {
                // Vulnerable: Exposing database errors
                reject({
                    error: 'Authentication failed',
                    details: error.message,
                    query: query,
                    sqlState: error.sqlState
                });
                return;
            }
            
            if (results.length === 0) {
                // Vulnerable: Exposing user enumeration info
                reject({
                    error: username.includes('@') ? 
                           'Invalid email address' : 
                           'Username does not exist',
                    timestamp: new Date(),
                    attemptedUsername: username
                });
                return;
            }
            
            resolve(results[0]);
        });
    });
}