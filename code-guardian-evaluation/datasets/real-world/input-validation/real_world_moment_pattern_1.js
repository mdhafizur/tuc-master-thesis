// Vulnerability pattern found in moment
// CWE: CWE-20
// Severity: medium
// Source: moment - Pattern Analysis
// Vulnerable lines: [1]

// Extracted from real project file
// Line 2428:         var i,
// Line 2429:             l,
// Line 2430:             string = config._i,
// Line 2431:             match = extendedIsoRegex.exec(string) || basicIsoRegex.exec(string),
// Line 2432:             allowTime,
// Line 2433:             dateFormat,
// Line 2434:             timeFormat,
// Line 2435:             tzFormat,
// Line 2436:             isoDatesLen = isoDates.length,
// Line 2437:             isoTimesLen = isoTimes.length;