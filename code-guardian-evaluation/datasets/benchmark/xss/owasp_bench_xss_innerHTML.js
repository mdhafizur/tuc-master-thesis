// XSS via innerHTML assignment (OWASP Benchmark)
// CWE: CWE-79
// Severity: high
// Source: OWASP Benchmark XSS-01
// Vulnerable lines: [11, 16]

// OWASP Benchmark: XSS via innerHTML
function displayUserProfile(userName, userBio) {
    const profileContainer = document.getElementById('profileContainer');
    
    // Vulnerable: Unescaped template literal in innerHTML
    const profileHtml = `
        <div class="profile">
            <h2>Profile: ${userName}</h2>
            <div class="bio">${userBio}</div>
        </div>
    `;
    
    profileContainer.innerHTML = profileHtml;
}

function showAlert(message) {
    // Vulnerable: Direct innerHTML assignment
    document.getElementById('alerts').innerHTML = "<div class='alert'>" + message + "</div>";
}