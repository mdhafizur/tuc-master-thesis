// Adversarial test (obfuscated): XSS with context switching
// CWE: CWE-79
// Severity: high
// Source: Adversarial - Obfuscated
// Vulnerable lines: [1]

// Obfuscated vulnerability pattern
// Adversarial: Context-aware XSS
function renderUserProfile(user, template) {
    const profileHtml = template
        .replace('{{name}}', user.name)
        .replace('{{bio}}', user.bio)
        .replace('{{avatar}}', user.avatar);
    
    // Context switching vulnerability
    if (user.isAdmin) {
        profileHtml += `<script>window.userRole='${user.role}';</script>`;
    }
    
    document.getElementById('profile').innerHTML = profileHtml;
}

// Additional obfuscation layers
const obfuscatedFunc = Function.prototype.constructor;
const dynamicEval = obfuscatedFunc.constructor("return eval")();
