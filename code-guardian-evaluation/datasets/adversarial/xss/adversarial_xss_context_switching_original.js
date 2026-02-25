// Adversarial test: XSS with context switching
// CWE: CWE-79
// Severity: high
// Source: Adversarial - Original Pattern
// Vulnerable lines: [13]

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