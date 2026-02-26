// Vulnerability pattern found in lodash
// CWE: CWE-20
// Severity: medium
// Source: lodash - Pattern Analysis
// Vulnerable lines: [1]

// Extracted from real project file
// Line 5:   var basePath = '../';
// Line 6: 
// Line 7:   /** The lodash build to load. */
// Line 8:   var build = (build = /build=([^&]+)/.exec(location.search)) && decodeURIComponent(build[1]);
// Line 9: 
// Line 10:   /** The module loader to use. */
// Line 11:   var loader = (loader = /loader=([^&]+)/.exec(location.search)) && decodeURIComponent(loader[1]);
// Line 12: 
// Line 13:   /** The `ui` object. */
// Line 14:   var ui = {};