'use strict';

/**
 * Snapshot test for evaluation/sast-fusion.js.
 * Run via: node evaluation/sast-fusion.snapshot.test.js
 */

const assert = require('assert');
const { fuseSastWithLlm, fusionSummary, rangesOverlap, categoriesAgree } = require('./sast-fusion');

// --- rangesOverlap -----------------------------------------------------
assert.strictEqual(rangesOverlap({ startLine: 1, endLine: 3 }, { startLine: 3, endLine: 5 }), true, 'touch at boundary counts as overlap');
assert.strictEqual(rangesOverlap({ startLine: 1, endLine: 2 }, { startLine: 4, endLine: 5 }), false, 'non-overlapping ranges');
assert.strictEqual(rangesOverlap({ startLine: 5, endLine: 10 }, { startLine: 6, endLine: 8 }), true, 'inner range');

// --- categoriesAgree ---------------------------------------------------
assert.strictEqual(categoriesAgree('SQL Injection', 'sqli via concat'), true, 'both normalize to sql-injection');
assert.strictEqual(categoriesAgree('XSS', 'Cross-Site Scripting'), true, 'both normalize to xss');
assert.strictEqual(categoriesAgree('Code Injection', 'Insecure Deserialization'), false, 'different canonicals');
assert.strictEqual(categoriesAgree('something weird', 'another weird'), false, 'both other → no agreement');
assert.strictEqual(categoriesAgree('', 'SQL Injection'), false, 'empty on one side');

// --- fuseSastWithLlm: empty-input edge cases ---------------------------
assert.deepStrictEqual(fuseSastWithLlm([], [{ type: 'SQL Injection', startLine: 1, endLine: 1 }]), [], 'empty LLM → empty result');

const llmOnly = [{ type: 'XSS', message: 'x', startLine: 5, endLine: 5, confidence: 0.5 }];
const fusedNoSast = fuseSastWithLlm(llmOnly, []);
assert.deepStrictEqual(fusedNoSast, llmOnly, 'no SAST → pass through untouched');

// --- fuseSastWithLlm: happy path (promotion) ---------------------------
const llmIssues = [
    { type: 'SQL Injection', message: 'concat into query', startLine: 4, endLine: 6, confidence: 0.5 },
    { type: 'XSS', message: 'innerHTML', startLine: 10, endLine: 11, confidence: 0.5 }
];
const sastIssues = [
    { type: 'SQL Injection', startLine: 5, endLine: 5, ruleId: 'semgrep.sqli.concat' },
    { type: 'Command Injection', startLine: 20, endLine: 20, ruleId: 'semgrep.cmdi' }
];
const fused = fuseSastWithLlm(llmIssues, sastIssues);
assert.strictEqual(fused.length, 2, 'preserves length');
assert.strictEqual(fused[0].confidence, 1.0, 'SQL Injection LLM finding is promoted');
assert.strictEqual(fused[0].detectionSource, 'hybrid', 'SQL Injection gets hybrid tag');
assert.strictEqual(fused[0].fusedWith, 'semgrep.sqli.concat', 'fusedWith is attached');
assert.strictEqual(fused[1].confidence, 0.5, 'XSS LLM finding keeps original confidence');
assert.strictEqual(fused[1].detectionSource, undefined, 'XSS not tagged hybrid (no matching SAST)');

// --- fuseSastWithLlm: category mismatch prevents promotion -------------
const llmIssuesMixedCategory = [
    { type: 'Deserialization', message: 'eval on user input', startLine: 1, endLine: 3, confidence: 0.7 }
];
const sastIssuesDifferentCategory = [
    { type: 'XSS', startLine: 2, endLine: 2, ruleId: 'semgrep.xss' }
];
const fusedMixed = fuseSastWithLlm(llmIssuesMixedCategory, sastIssuesDifferentCategory);
assert.strictEqual(fusedMixed[0].confidence, 0.7, 'same-line but different category does not promote');
assert.strictEqual(fusedMixed[0].detectionSource, undefined);

// --- fusionSummary ------------------------------------------------------
const summary = fusionSummary(fused);
assert.deepStrictEqual(summary, { hybrid: 1, llmOnly: 1, total: 2 }, 'summary counts correctly');

console.log('sast-fusion snapshot OK');
