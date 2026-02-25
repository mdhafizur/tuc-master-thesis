// XSS vulnerability in DOM manipulation (Devign-style)
// CWE: CWE-79
// Severity: high
// Source: Devign Pattern (fallback)
// Vulnerable lines: [5, 9, 10]

// Devign-style XSS vulnerability
function displayMessage(userMessage) {
    const container = document.getElementById('messageContainer');
    
    // Vulnerable: Unescaped HTML insertion
    container.innerHTML = '<div class="message">' + userMessage + '</div>';
}

function updateProfile(name, bio) {
    document.getElementById('userName').innerHTML = name;
    document.getElementById('userBio').innerHTML = bio;
}