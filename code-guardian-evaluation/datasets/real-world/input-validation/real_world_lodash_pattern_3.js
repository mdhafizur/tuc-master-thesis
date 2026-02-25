// Vulnerability pattern found in lodash
// CWE: CWE-20
// Severity: medium
// Source: lodash - Pattern Analysis
// Vulnerable lines: [1]

// Extracted from real project file
// Line 242:   });
// Line 243: 
// Line 244:   /** The basename of the lodash file to test. */
// Line 245:   var basename = /[\w.-]+$/.exec(filePath)[0];
// Line 246: 
// Line 247:   /** Used to indicate testing a modularized build. */
// Line 248:   var isModularize = ui.isModularize;
// Line 249: 
// Line 250:   /** Detect if testing `npm` modules. */
// Line 251:   var isNpm = isModularize && /\bnpm\b/.test([ui.buildPath, ui.urlParams.build]);