// Adversarial test (minimal): Nested prototype pollution
// CWE: CWE-1321
// Severity: medium
// Source: Adversarial - Minimal
// Vulnerable lines: [1]

function merge(obj, src) { for(let k in src) obj[k] = src[k]; }