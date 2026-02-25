// Lodash template prototype pollution (Big-Vul style)
// CWE: CWE-1321
// Severity: high
// Source: Big-Vul Pattern (CVE-2021-23337)
// CVE: CVE-2021-23337
// Vulnerable lines: [7, 15]

// Big-Vul style lodash template vulnerability
function template(templateString, data) {
    // Vulnerable: Template injection via prototype pollution
    let result = templateString;
    
    for (let key in data) {
        // Vulnerable: No validation of key names
        const regex = new RegExp('\\{\\{\\s*' + key + '\\s*\\}\\}', 'g');
        result = result.replace(regex, data[key]);
    }
    
    return result;
}

function processTemplate(userInput, templateData) {
    // Vulnerable: User input affects template processing
    const merged = Object.assign({}, templateData, JSON.parse(userInput));
    
    return template('Hello {{name}}, your role is {{role}}', merged);
}