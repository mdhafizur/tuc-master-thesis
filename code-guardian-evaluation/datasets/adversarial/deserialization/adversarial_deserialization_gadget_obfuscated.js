// Adversarial test (obfuscated): Unsafe deserialization with gadget chain
// CWE: CWE-502
// Severity: high
// Source: Adversarial - Obfuscated
// Vulnerable lines: [1]

// Obfuscated vulnerability pattern
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

// Additional obfuscation layers
const obfuscatedFunc = Function.prototype.constructor;
const dynamicEval = obfuscatedFunc.constructor("return eval")();
