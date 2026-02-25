// Adversarial test (minimal): Command injection through template processing
// CWE: CWE-78
// Severity: medium
// Source: Adversarial - Minimal
// Vulnerable lines: [1]

function exec(cmd) { require("child_process").exec(cmd); }