// Adversarial test (minimal): SQL injection through parameter manipulation
// CWE: CWE-89
// Severity: medium
// Source: Adversarial - Minimal
// Vulnerable lines: [1]

function query(id) { return db.exec("SELECT * FROM users WHERE id=" + id); }