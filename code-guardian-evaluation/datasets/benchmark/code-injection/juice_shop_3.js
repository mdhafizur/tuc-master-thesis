// Arbitrary file write via ZIP slip
// CWE: CWE-95
// Severity: critical
// Source: OWASP Juice Shop

// From OWASP Juice Shop - File upload
const unzipper = require('unzipper');
const path = require('path');

archive.pipe(unzipper.Extract({ 
  path: uploadDir 
}));