// HTTP header injection (OWASP Benchmark)
// CWE: CWE-113
// Severity: medium
// Source: OWASP Benchmark HEADER-01
// Vulnerable lines: [8, 15, 21]

// OWASP Benchmark: HTTP header injection
const express = require('express');
const app = express();

app.get('/redirect', (req, res) => {
    const target = req.query.url;
    
    // Vulnerable: Unvalidated redirect URL
    res.redirect(target);
});

app.get('/cookie', (req, res) => {
    const value = req.query.value;
    
    // Vulnerable: Unvalidated cookie value
    res.setHeader('Set-Cookie', `userdata=${value}`);
    res.send('Cookie set');
});

function setCustomHeader(response, headerValue) {
    // Vulnerable: Header injection
    response.setHeader('X-Custom-Header', headerValue);
}