// Vulnerability pattern found in serialize-javascript
// CWE: CWE-20
// Severity: medium
// Source: serialize-javascript - Pattern Analysis
// Vulnerable lines: [1]

// Extracted from real project file
// Line 31:         });
// Line 32: 
// Line 33:         it('should deserialize "undefined" to `undefined`', function () {
// Line 34:             strictEqual(eval(serialize()), undefined);
// Line 35:             strictEqual(eval(serialize(undefined)), undefined);
// Line 36:         });
// Line 37:     });
// Line 38: 
// Line 39:     describe('null', function () {
// Line 40:         it('should serialize `null` to a string', function () {