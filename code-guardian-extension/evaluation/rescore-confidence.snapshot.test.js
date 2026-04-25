'use strict';

/**
 * Snapshot test for rescore-metrics.js inter-run confidence computation.
 * Run via: node evaluation/rescore-confidence.snapshot.test.js
 */

const assert = require('assert');
const { annotateInterRunConfidence, issuesMatchAcrossRuns, applyGate } = require('./rescore-metrics');

// --- issuesMatchAcrossRuns ---------------------------------------------
assert.strictEqual(
    issuesMatchAcrossRuns(
        { type: 'SQL Injection', startLine: 4, endLine: 6 },
        { type: 'SQLi', startLine: 5, endLine: 5 }
    ),
    true,
    'overlap + same canonical category → match'
);
assert.strictEqual(
    issuesMatchAcrossRuns(
        { type: 'SQL Injection', startLine: 4, endLine: 6 },
        { type: 'XSS', startLine: 5, endLine: 5 }
    ),
    false,
    'overlap but different canonical → no match'
);
assert.strictEqual(
    issuesMatchAcrossRuns(
        { type: 'SQL Injection', startLine: 4, endLine: 6 },
        { type: 'SQL Injection', startLine: 10, endLine: 12 }
    ),
    false,
    'same category but no line overlap → no match'
);

// --- annotateInterRunConfidence: 3-run case, all agree ----------------
{
    const detailedResults = [
        { testCaseId: 'tc-1', run: 1, detectedIssuesRaw: [
            { type: 'SQL Injection', startLine: 5, endLine: 5, message: 'concat' }
        ]},
        { testCaseId: 'tc-1', run: 2, detectedIssuesRaw: [
            { type: 'SQLi', startLine: 5, endLine: 6, message: 'taint' }
        ]},
        { testCaseId: 'tc-1', run: 3, detectedIssuesRaw: [
            { type: 'SQL Injection', startLine: 4, endLine: 5, message: 'concat' }
        ]}
    ];
    const sum = annotateInterRunConfidence(detailedResults);
    assert.strictEqual(sum.groupsWithMultipleRuns, 1);
    assert.strictEqual(sum.issuesAnnotated, 3);
    for (const dr of detailedResults) {
        assert.strictEqual(dr.detectedIssuesRaw[0].confidence, 1.0,
            '3/3 agreement → confidence 1.0 (run ' + dr.run + ')');
    }
}

// --- 3-run case, partial agreement (2/3) ------------------------------
{
    const detailedResults = [
        { testCaseId: 'tc-2', run: 1, detectedIssuesRaw: [
            { type: 'XSS', startLine: 8, endLine: 8 }
        ]},
        { testCaseId: 'tc-2', run: 2, detectedIssuesRaw: [
            { type: 'XSS', startLine: 8, endLine: 9 }
        ]},
        { testCaseId: 'tc-2', run: 3, detectedIssuesRaw: [
            { type: 'Command Injection', startLine: 20, endLine: 20 }
        ]}
    ];
    annotateInterRunConfidence(detailedResults);
    assert.strictEqual(detailedResults[0].detectedIssuesRaw[0].confidence, 2 / 3, 'run1 XSS sees self+run2');
    assert.strictEqual(detailedResults[1].detectedIssuesRaw[0].confidence, 2 / 3, 'run2 XSS sees self+run1');
    assert.strictEqual(detailedResults[2].detectedIssuesRaw[0].confidence, 1 / 3, 'run3 cmdinj alone');
}

// --- single run case → no annotation ---------------------------------
{
    const detailedResults = [
        { testCaseId: 'tc-3', run: 1, detectedIssuesRaw: [
            { type: 'XSS', startLine: 1, endLine: 1 }
        ]}
    ];
    const sum = annotateInterRunConfidence(detailedResults);
    assert.strictEqual(sum.groupsWithMultipleRuns, 0);
    assert.strictEqual(sum.issuesAnnotated, 0);
    assert.strictEqual(detailedResults[0].detectedIssuesRaw[0].confidence, undefined,
        'single-run case leaves confidence unset (gate treats as 0.5)');
}

// --- gate respects annotated confidence -------------------------------
{
    const issues = [
        { type: 'SQL Injection', confidence: 1.0 },
        { type: 'XSS', confidence: 2 / 3 },
        { type: 'Other', confidence: 1 / 3 },
        { type: 'NoConfField' }
    ];
    assert.strictEqual(applyGate(issues, 0).length, 4, 'threshold 0 keeps all');
    assert.strictEqual(applyGate(issues, 0.5).length, 3, 'threshold 0.5 keeps ≥0.5 incl. undefined-default');
    assert.strictEqual(applyGate(issues, 0.7).length, 1, 'threshold 0.7 keeps only 1.0');
    assert.strictEqual(applyGate(issues, 1.0).length, 1, 'threshold 1.0 keeps unanimous only');
}

// --- mixed multi-test-case correctness --------------------------------
{
    const detailedResults = [
        { testCaseId: 'tcA', run: 1, detectedIssuesRaw: [{ type: 'XSS', startLine: 1, endLine: 1 }] },
        { testCaseId: 'tcA', run: 2, detectedIssuesRaw: [{ type: 'XSS', startLine: 1, endLine: 1 }] },
        { testCaseId: 'tcB', run: 1, detectedIssuesRaw: [{ type: 'SQL Injection', startLine: 5, endLine: 5 }] }
    ];
    const sum = annotateInterRunConfidence(detailedResults);
    assert.strictEqual(sum.groupsWithMultipleRuns, 1, 'only tcA has 2 runs');
    assert.strictEqual(detailedResults[0].detectedIssuesRaw[0].confidence, 1.0, 'tcA run1 unanimous');
    assert.strictEqual(detailedResults[1].detectedIssuesRaw[0].confidence, 1.0, 'tcA run2 unanimous');
    assert.strictEqual(detailedResults[2].detectedIssuesRaw[0].confidence, undefined, 'tcB single-run untouched');
}

console.log('rescore-metrics inter-run confidence snapshot OK');
