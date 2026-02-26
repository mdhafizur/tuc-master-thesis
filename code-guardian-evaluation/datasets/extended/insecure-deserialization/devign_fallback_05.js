// Insecure deserialization vulnerability (Devign-style)
// CWE: CWE-502
// Severity: critical
// Source: Devign Pattern (fallback)
// Vulnerable lines: [3, 12]

// Devign-style insecure deserialization
function processUserData(serializedData) {
    // Vulnerable: Using eval for deserialization
    const userData = eval('(' + serializedData + ')');
    
    if (userData.isAdmin) {
        return getAdminData();
    }
    
    return getUserData(userData.id);
}

function deserializeConfig(configString) {
    // Another vulnerable pattern
    return eval('config = ' + configString);
}