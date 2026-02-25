// XSS in dynamic content generation (OWASP Benchmark pattern)
// CWE: CWE-79
// Severity: high
// Source: OWASP Benchmark (adapted)
// Vulnerable lines: [9]

// OWASP Benchmark pattern adapted to JavaScript
function generateUserProfile(userName, userBio) {
    const profileHtml = `
        <div class="profile">
            <h2>Profile: ${userName}</h2>
            <div class="bio">${userBio}</div>
        </div>
    `;
    
    // Vulnerable: Unescaped template literal
    document.getElementById('profileContainer').innerHTML = profileHtml;
}

function displayProfile(userData) {
    generateUserProfile(userData.name, userData.bio);
}