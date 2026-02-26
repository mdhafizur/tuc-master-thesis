// SQL injection vulnerability (Big-Vul style)
// CWE: CWE-89
// Severity: high
// Source: Big-Vul Pattern (fallback)
// CVE: CVE-2021-EXAMPLE
// Vulnerable lines: [3]

// Big-Vul style vulnerability
function searchRecords(term) {
    const sql = "SELECT * FROM records WHERE title LIKE '%" + term + "%'";
    return db.query(sql);
}