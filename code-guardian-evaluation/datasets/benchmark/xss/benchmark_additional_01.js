// DOM-based XSS via URL parameters
// CWE: CWE-79
// Severity: high
// Source: Additional Benchmark Pattern
// Vulnerable lines: [6]

// Additional benchmark: DOM-based XSS
function parseUrlParams() {
    const params = new URLSearchParams(window.location.search);
    const message = params.get('message');
    
    // Vulnerable: Direct DOM manipulation
    if (message) {
        document.getElementById('content').innerHTML = message;
    }
}

window.onload = parseUrlParams;