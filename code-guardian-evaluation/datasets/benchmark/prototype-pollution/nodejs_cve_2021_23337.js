// Prototype pollution in lodash merge function
// CWE: CWE-1321
// Severity: high
// Source: CVE-2021-23337
// CVE: CVE-2021-23337
// Vulnerable lines: [5]

// CVE-2021-23337: Prototype pollution in lodash
const _ = require('lodash');

function mergeUserSettings(defaultSettings, userPreferences) {
    // Vulnerable: lodash.merge susceptible to prototype pollution
    return _.merge({}, defaultSettings, userPreferences);
}

function updateUserConfig(userId, configData) {
    const defaults = {
        theme: 'light',
        notifications: true,
        language: 'en'
    };
    
    // Parse user input (potentially malicious)
    const userConfig = JSON.parse(configData);
    
    // This can pollute Object.prototype if userConfig contains __proto__
    const mergedConfig = mergeUserSettings(defaults, userConfig);
    
    return mergedConfig;
}

// Attack payload example:
// {"__proto__": {"polluted": true}}