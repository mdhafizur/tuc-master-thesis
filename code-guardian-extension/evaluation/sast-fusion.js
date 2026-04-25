'use strict';

/**
 * SAST × LLM fusion for the thesis Phase 2 refinement.
 *
 * Pure, deterministic function. Given LLM findings and SAST findings for the
 * SAME test case, promote any LLM finding whose line range overlaps a SAST
 * finding AND whose canonical category matches. Promoted findings get:
 *   - confidence: 1.0 (SAST agreement is the strongest signal we have)
 *   - detectionSource: 'hybrid'
 *   - fusedWith: <semgrep ruleId>   (for traceability in the run JSON)
 *
 * LLM-only findings (no SAST overlap) keep their original confidence and
 * detectionSource — the downstream confidence gate decides whether to drop them.
 *
 * The TS twin at src/sastBridge.ts must stay in sync. A snapshot test in
 * evaluation/sast-fusion.snapshot.test.js asserts deterministic behavior on a
 * fixed fixture set.
 */

const taxonomy = require('./category-taxonomy');

function rangesOverlap(a, b) {
    const aStart = Number.isFinite(a.startLine) ? a.startLine : 1;
    const aEnd = Number.isFinite(a.endLine) ? a.endLine : aStart;
    const bStart = Number.isFinite(b.startLine) ? b.startLine : 1;
    const bEnd = Number.isFinite(b.endLine) ? b.endLine : bStart;
    return Math.max(aStart, bStart) <= Math.min(aEnd, bEnd);
}

function categoriesAgree(llmType, sastType) {
    const c1 = taxonomy.normalizeCategory(llmType);
    const c2 = taxonomy.normalizeCategory(sastType);
    // Only treat as agreement if BOTH normalize to a specific category.
    // 'other' on either side means we don't have enough signal to promote.
    return c1 !== 'other' && c1 === c2;
}

function fuseSastWithLlm(llmIssues, sastIssues) {
    if (!Array.isArray(llmIssues) || llmIssues.length === 0) {
        return [];
    }
    if (!Array.isArray(sastIssues) || sastIssues.length === 0) {
        // No SAST evidence — pass through unchanged.
        return llmIssues.map(issue => ({ ...issue }));
    }

    return llmIssues.map(llm => {
        const match = sastIssues.find(sast =>
            rangesOverlap(llm, sast) && categoriesAgree(llm.type, sast.type)
        );
        if (match) {
            return {
                ...llm,
                confidence: 1.0,
                detectionSource: 'hybrid',
                fusedWith: match.ruleId || match.tool || 'sast'
            };
        }
        return { ...llm };
    });
}

/**
 * Summary counts for reporting in the run JSON. Does not mutate inputs.
 */
function fusionSummary(fusedIssues) {
    let hybrid = 0;
    let llmOnly = 0;
    for (const issue of fusedIssues) {
        if (issue.detectionSource === 'hybrid') {
            hybrid++;
        } else {
            llmOnly++;
        }
    }
    return { hybrid, llmOnly, total: fusedIssues.length };
}

module.exports = {
    fuseSastWithLlm,
    fusionSummary,
    rangesOverlap,
    categoriesAgree
};
