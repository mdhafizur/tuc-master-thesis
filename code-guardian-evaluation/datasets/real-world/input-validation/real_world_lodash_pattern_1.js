// Vulnerability pattern found in lodash
// CWE: CWE-20
// Severity: medium
// Source: lodash - Pattern Analysis
// Vulnerable lines: [1]

// Extracted from real project file
// Line 1478: 
// Line 1479:     /** Used to detect methods masquerading as native. */
// Line 1480:     var maskSrcKey = (function() {
// Line 1481:       var uid = /[^.]+$/.exec(coreJsData && coreJsData.keys && coreJsData.keys.IE_PROTO || '');
// Line 1482:       return uid ? ('Symbol(src)_1.' + uid) : '';
// Line 1483:     }());
// Line 1484: 
// Line 1485:     /**
// Line 1486:      * Used to resolve the
// Line 1487:      * [`toStringTag`](http://ecma-international.org/ecma-262/7.0/#sec-object.prototype.tostring)