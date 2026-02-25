// Adversarial test (minimal): Unsafe deserialization with gadget chain
// CWE: CWE-502
// Severity: medium
// Source: Adversarial - Minimal
// Vulnerable lines: [1]

function load(data) { return Object.assign({}, JSON.parse(data)); }