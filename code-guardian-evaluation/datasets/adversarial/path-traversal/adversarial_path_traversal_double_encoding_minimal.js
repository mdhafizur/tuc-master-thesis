// Adversarial test (minimal): Path traversal with encoding bypass
// CWE: CWE-22
// Severity: medium
// Source: Adversarial - Minimal
// Vulnerable lines: [1]

function readFile(path) { return fs.readFileSync("./files/" + path); }