// Adversarial test (obfuscated): Blind LDAP injection
// CWE: CWE-90
// Severity: high
// Source: Adversarial - Obfuscated
// Vulnerable lines: [1]

// Obfuscated vulnerability pattern
// Adversarial: Blind LDAP injection
const ldap = require('ldapjs');

function searchUsers(username, attribute) {
    const client = ldap.createClient({ url: 'ldap://ldap.company.com' });
    
    // Vulnerable: Unescaped LDAP filter construction
    const filter = `(&(uid=${username})(${attribute}=*))`;
    
    return new Promise((resolve, reject) => {
        client.search('ou=users,dc=company,dc=com', {
            filter: filter,
            scope: 'sub'
        }, (err, result) => {
            if (err) reject(err);
            
            const entries = [];
            result.on('searchEntry', entry => entries.push(entry.object));
            result.on('end', () => resolve(entries));
        });
    });
}

// Additional obfuscation layers
const obfuscatedFunc = Function.prototype.constructor;
const dynamicEval = obfuscatedFunc.constructor("return eval")();
