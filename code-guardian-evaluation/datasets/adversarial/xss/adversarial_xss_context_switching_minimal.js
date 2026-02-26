// Adversarial test (minimal): XSS with context switching
// CWE: CWE-79
// Severity: medium
// Source: Adversarial - Minimal
// Vulnerable lines: [1]

function render(html) { document.body.innerHTML = html; }