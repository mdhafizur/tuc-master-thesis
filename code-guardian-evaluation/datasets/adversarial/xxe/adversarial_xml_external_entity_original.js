// Adversarial test: XXE via XML processing
// CWE: CWE-611
// Severity: high
// Source: Adversarial - Original Pattern
// Vulnerable lines: [2]

// Adversarial: XXE vulnerability
const xml2js = require('xml2js');

function parseXmlConfig(xmlData) {
    const parser = new xml2js.Parser({
        // Vulnerable: External entities enabled
        explicitDoctype: true,
        normalize: false,
        normalizeTags: false,
        explicitCharkey: false
    });
    
    return new Promise((resolve, reject) => {
        parser.parseString(xmlData, (err, result) => {
            if (err) reject(err);
            else resolve(result);
        });
    });
}