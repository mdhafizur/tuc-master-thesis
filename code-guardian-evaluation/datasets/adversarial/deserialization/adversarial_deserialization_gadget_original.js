// Adversarial test: Unsafe deserialization with gadget chain
// CWE: CWE-502
// Severity: high
// Source: Adversarial - Original Pattern
// Vulnerable lines: [4, 12]

// Adversarial: Deserialization gadget chain
class UserSession {
    constructor(data) {
        Object.assign(this, data);
    }
    
    toJSON() {
        return { ...this, serializedAt: Date.now() };
    }
    
    static fromJSON(jsonStr) {
        const data = JSON.parse(jsonStr);
        // Vulnerable: Automatic property assignment
        return new UserSession(data);
    }
}

function loadUserSession(sessionData) {
    return UserSession.fromJSON(sessionData);
}