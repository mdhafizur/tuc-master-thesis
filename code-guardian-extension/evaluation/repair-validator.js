'use strict';

/**
 * JS twin of src/repairValidator.ts. Used by the evaluation harness to compute
 * `autoApplicable` per repair and the `autoApplicableRate` aggregate.
 *
 * Both twins must stay in sync. A snapshot test in
 * evaluation/repair-validator.snapshot.test.js asserts identical behavior on a
 * fixed fixture set.
 */

const { parse } = require('@babel/parser');

const PROSE_INDICATORS = [
    /^you\s+should/i,
    /^to\s+fix/i,
    /^the\s+vulnerability/i,
    /^use\s+(a\s+)?(parameterized|prepared|bind)/i,
    /^replace\s+with/i,
    /^consider\s+using/i,
    /^make\s+sure/i,
    /^this\s+code/i,
    /^example\s*:/i
];

const BABEL_PLUGINS = [
    'jsx',
    'typescript',
    'classProperties',
    'asyncGenerators',
    'objectRestSpread',
    'optionalChaining',
    'nullishCoalescingOperator',
    'dynamicImport',
    'topLevelAwait',
    'exportDefaultFrom',
    'exportNamespaceFrom',
    'numericSeparator',
    'logicalAssignment'
];

function stripFencesAndQuotes(raw) {
    let s = String(raw).trim();
    const fenceStart = /^```[a-zA-Z]*\s*\n?/;
    if (fenceStart.test(s)) {
        s = s.replace(fenceStart, '');
        s = s.replace(/\n?```\s*$/, '');
    }
    if (s.startsWith('`') && s.endsWith('`') && s.length > 1) {
        s = s.slice(1, -1).trim();
    }
    return s.trim();
}

function looksLikeProse(s) {
    if (s.length === 0) return true;
    for (const re of PROSE_INDICATORS) {
        if (re.test(s)) return true;
    }
    return false;
}

function validateRepair(fix) {
    if (typeof fix !== 'string') {
        return { valid: false, reason: 'not_a_string' };
    }
    const cleaned = stripFencesAndQuotes(fix);
    if (cleaned.length === 0) {
        return { valid: false, reason: 'empty' };
    }
    if (looksLikeProse(cleaned)) {
        return { valid: false, reason: 'prose_not_code' };
    }

    try {
        parse(cleaned, {
            sourceType: 'module',
            plugins: BABEL_PLUGINS,
            errorRecovery: false,
            allowReturnOutsideFunction: true,
            allowAwaitOutsideFunction: true,
            allowSuperOutsideMethod: true,
            allowUndeclaredExports: true
        });
        return { valid: true, parsedAs: 'module' };
    } catch (e1) {
        try {
            parse(cleaned, {
                sourceType: 'script',
                plugins: BABEL_PLUGINS,
                errorRecovery: false,
                allowReturnOutsideFunction: true,
                allowAwaitOutsideFunction: true,
                allowSuperOutsideMethod: true
            });
            return { valid: true, parsedAs: 'script' };
        } catch (e2) {
            try {
                parse(`(() => { ${cleaned} })`, {
                    sourceType: 'module',
                    plugins: BABEL_PLUGINS,
                    errorRecovery: false
                });
                return { valid: true, parsedAs: 'expression' };
            } catch (e3) {
                const msg = (e2.message || e1.message || e3.message || '').slice(0, 120);
                return { valid: false, reason: `parse_error: ${msg}` };
            }
        }
    }
}

/**
 * Aggregate auto-applicable counts across an array of detected issues. Walks
 * each issue's `suggestedFix` (string) and increments counters. Returns
 * `{ totalRepairs, autoApplicable, autoApplicableRate, byReason }` where
 * `autoApplicableRate` is in [0,1].
 */
function aggregateAutoApplicable(detectedIssuesList) {
    let total = 0;
    let valid = 0;
    const byReason = {};
    for (const issues of detectedIssuesList) {
        if (!Array.isArray(issues)) continue;
        for (const issue of issues) {
            const fix = issue && issue.suggestedFix;
            if (fix === undefined || fix === null || fix === '') continue;
            total++;
            const result = validateRepair(fix);
            if (result.valid) {
                valid++;
            } else {
                byReason[result.reason] = (byReason[result.reason] || 0) + 1;
            }
        }
    }
    return {
        totalRepairs: total,
        autoApplicable: valid,
        autoApplicableRate: total > 0 ? valid / total : 0,
        byReason
    };
}

module.exports = { validateRepair, aggregateAutoApplicable, stripFencesAndQuotes };
