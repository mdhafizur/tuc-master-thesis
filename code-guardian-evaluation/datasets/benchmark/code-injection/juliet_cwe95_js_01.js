// Code injection via eval (adapted from Juliet CWE95)
// CWE: CWE-95
// Severity: critical
// Source: Juliet Test Suite (adapted)
// Vulnerable lines: [5]

// Adapted from Juliet Test Suite CWE-95
function processUserCommand(command) {
    try {
        // CWE-95: Code injection via eval()
        const result = eval("(" + command + ")");
        return {
            success: true,
            result: result
        };
    } catch (error) {
        return {
            success: false,
            error: error.message
        };
    }
}

// Example usage that enables code injection
function executeUserScript(scriptContent) {
    return processUserCommand(scriptContent);
}