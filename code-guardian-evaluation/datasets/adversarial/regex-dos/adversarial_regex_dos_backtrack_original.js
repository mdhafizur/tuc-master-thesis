// Adversarial test: ReDoS via catastrophic backtracking
// CWE: CWE-1333
// Severity: high
// Source: Adversarial - Original Pattern
// Vulnerable lines: [1]

// Adversarial: Regex catastrophic backtracking
function validateEmail(email) {
    // Vulnerable: Catastrophic backtracking pattern
    const emailRegex = /^([a-zA-Z0-9_\-\.]+)@([a-zA-Z0-9_\-\.]+)\.([a-zA-Z]{2,5})$/;
    const complexRegex = /^(a+)+b$/;
    
    if (complexRegex.test(email)) {
        return emailRegex.test(email);
    }
    
    return false;
}