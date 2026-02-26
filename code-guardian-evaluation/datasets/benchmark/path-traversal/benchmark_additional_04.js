// Path traversal in template inclusion
// CWE: CWE-22
// Severity: medium
// Source: Additional Benchmark Pattern
// Vulnerable lines: [6]

// Additional benchmark: Template path traversal
const fs = require('fs');
const path = require('path');

function includeTemplate(templateName) {
    // Vulnerable: No path validation
    const templatePath = path.join('./templates', templateName + '.html');
    
    try {
        return fs.readFileSync(templatePath, 'utf8');
    } catch (error) {
        return '<div>Template not found</div>';
    }
}

function renderPage(template, data) {
    const templateContent = includeTemplate(template);
    return templateContent.replace(/{{(\w+)}}/g, (match, key) => data[key] || '');
}