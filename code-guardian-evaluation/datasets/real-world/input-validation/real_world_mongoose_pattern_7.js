// Vulnerability pattern found in mongoose
// CWE: CWE-20
// Severity: medium
// Source: mongoose - Pattern Analysis
// Vulnerable lines: [1]

// Extracted from real project file
// Line 974:     const n = await N.create({ g: m._id });
// Line 975:     const o = await O.create({ i: n._id });
// Line 976: 
// Line 977:     const doc = await O.findOne({ _id: o._id }).populate('i').exec();
// Line 978:     const finalDoc = await doc.populate('i.g');
// Line 979: 
// Line 980:     assert.ok(finalDoc.populated('i.g'));
// Line 981:     assert.ok(finalDoc.i.populated('g'));
// Line 982:   });
// Line 983: 