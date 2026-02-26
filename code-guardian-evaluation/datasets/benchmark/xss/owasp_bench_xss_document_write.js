// XSS via document.write (OWASP Benchmark)
// CWE: CWE-79
// Severity: high
// Source: OWASP Benchmark XSS-02
// Vulnerable lines: [3, 15]

// OWASP Benchmark: XSS via document.write
function renderPage(title, content) {
    // Vulnerable: Unescaped content in document.write
    document.write(`
        <html>
            <head><title>${title}</title></head>
            <body>
                <h1>${title}</h1>
                <div>${content}</div>
            </body>
        </html>
    `);
}

function insertScript(scriptContent) {
    // Vulnerable: Direct script injection
    document.write("<script>" + scriptContent + "</script>");
}