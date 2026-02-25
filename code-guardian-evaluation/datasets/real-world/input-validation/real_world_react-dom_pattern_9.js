// Vulnerability pattern found in react-dom
// CWE: CWE-20
// Severity: medium
// Source: react-dom - Pattern Analysis
// Vulnerable lines: [1]

// Extracted from real project file
// Line 15: 
// Line 16: function executeCommand(command) {
// Line 17:   return new Promise(_resolve =>
// Line 18:     exec(command, error => {
// Line 19:       if (!error) {
// Line 20:         _resolve();
// Line 21:       } else {
// Line 22:         console.error(error);
// Line 23:         process.exit(1);
// Line 24:       }