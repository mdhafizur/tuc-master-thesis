// Server-Side Request Forgery in webhook
// CWE: CWE-918
// Severity: high
// Source: Additional Benchmark Pattern
// Vulnerable lines: [6, 13, 19]

// Additional benchmark: SSRF vulnerability
const axios = require('axios');

async function processWebhook(webhookUrl, data) {
    try {
        // Vulnerable: No URL validation
        const response = await axios.post(webhookUrl, data);
        return response.data;
    } catch (error) {
        throw new Error('Webhook failed');
    }
}

async function fetchExternalResource(url) {
    // Vulnerable: Unrestricted URL access
    const response = await fetch(url);
    return response.text();
}

function proxyRequest(targetUrl) {
    // Vulnerable: Open proxy functionality
    return fetch(targetUrl).then(r => r.text());
}