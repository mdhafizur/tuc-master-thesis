// LDAP injection vulnerability (OWASP Benchmark)
// CWE: CWE-90
// Severity: high
// Source: OWASP Benchmark LDAP-01
// Vulnerable lines: [10]

// OWASP Benchmark: LDAP injection
const ldap = require('ldapjs');

function authenticateUser(username, password) {
    const client = ldap.createClient({
        url: 'ldap://localhost:389'
    });
    
    // Vulnerable: Unescaped LDAP filter
    const filter = `(&(uid=${username})(userPassword=${password}))`;
    
    const searchOptions = {
        filter: filter,
        scope: 'sub'
    };
    
    client.search('dc=example,dc=com', searchOptions, (err, result) => {
        if (err) throw err;
        // Process results
    });
}