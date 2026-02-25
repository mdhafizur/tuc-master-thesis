// Cross-site scripting via innerHTML (adapted from Juliet CWE79)
// CWE: CWE-79
// Severity: high
// Source: Juliet Test Suite (adapted)
// Vulnerable lines: [6]

// Adapted from Juliet Test Suite CWE-79
function displayUserMessage(userInput) {
    const messageContainer = document.getElementById('messageArea');
    
    // CWE-79: XSS via innerHTML without sanitization
    messageContainer.innerHTML = "<div class='message'>" + userInput + "</div>";
    
    // Show the message
    messageContainer.style.display = 'block';
}

// Usage example that enables XSS
function handleFormSubmit() {
    const userMessage = document.getElementById('userInput').value;
    displayUserMessage(userMessage);
}