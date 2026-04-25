#!/usr/bin/env node

/**
 * Post-hoc metric rescoring.
 *
 * Usage:
 *   node evaluation/rescore-metrics.js <run.json> [--confidence <0..1>] [--out <path>]
 *
 * Reads a run JSON produced by evaluate-models.js, applies a confidence gate to
 * the stored per-case LLM findings, and re-computes per-case + aggregate
 * metrics. Output JSON is written next to the input (or to --out) with a
 * `.rescored-conf-NN.json` suffix.
 *
 * This script NEVER calls Ollama. It is strictly a deterministic replay of the
 * scoring pipeline at a different threshold, enabling threshold sweeps in
 * seconds rather than the ~7h of a full rerun.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const taxonomy = require('./category-taxonomy');
const { rangesOverlap, categoriesAgree } = require('./sast-fusion');

function parseArgs(argv) {
    const rest = [];
    let confidence = 0;
    let out = null;
    let computeConfidence = true; // default ON; --no-compute-confidence to disable
    for (let i = 0; i < argv.length; i++) {
        const a = argv[i];
        if (a === '--confidence' || a === '--confidence-threshold') {
            confidence = Number.parseFloat(argv[++i]);
        } else if (a === '--out') {
            out = argv[++i];
        } else if (a === '--no-compute-confidence') {
            computeConfidence = false;
        } else {
            rest.push(a);
        }
    }
    return { inputPath: rest[0], confidence, out, computeConfidence };
}

function applyGate(issues, threshold) {
    if (!Array.isArray(issues)) return [];
    if (!threshold || threshold <= 0) return issues;
    return issues.filter(issue => {
        const c = typeof issue.confidence === 'number' ? issue.confidence : 0.5;
        return c >= threshold;
    });
}

/**
 * Two findings from different runs are considered the same vulnerability if
 * their line ranges overlap AND their canonical categories agree. Mirrors the
 * matcher used by the in-extension consensus filter, but uses the harness's
 * explicit `type` field instead of the message-keyword heuristic.
 */
function issuesMatchAcrossRuns(a, b) {
    return rangesOverlap(a, b) && categoriesAgree(a.type, b.type);
}

/**
 * Compute per-issue confidence from inter-run agreement.
 *
 * For each (model, mode) result block, group `detailedResults` by `testCaseId`.
 * If a test case was evaluated N≥2 times, every issue in `detectedIssuesRaw`
 * (or `detectedIssues` if raw is absent) receives:
 *   confidence = (number of runs containing a matching issue, including self) / N
 *
 * Single-run test cases are left with `confidence` undefined; the gate treats
 * undefined as 0.5 (the single-pass default), matching the in-extension logic.
 *
 * The function MUTATES the issue objects in place. It does not move issues
 * between detailedResults entries — every run keeps its own findings; only the
 * confidence annotation differs.
 *
 * Returns a small summary object for logging.
 */
function annotateInterRunConfidence(detailedResults) {
    const summary = { groupsWithMultipleRuns: 0, totalGroups: 0, issuesAnnotated: 0 };
    if (!Array.isArray(detailedResults)) return summary;

    const groupsByCase = new Map();
    for (const dr of detailedResults) {
        if (!dr || !dr.testCaseId) continue;
        if (!groupsByCase.has(dr.testCaseId)) groupsByCase.set(dr.testCaseId, []);
        groupsByCase.get(dr.testCaseId).push(dr);
    }

    summary.totalGroups = groupsByCase.size;

    for (const [, runs] of groupsByCase) {
        const N = runs.length;
        if (N < 2) continue;
        summary.groupsWithMultipleRuns++;

        for (const run of runs) {
            const issues = Array.isArray(run.detectedIssuesRaw)
                ? run.detectedIssuesRaw
                : (Array.isArray(run.detectedIssues) ? run.detectedIssues : []);
            for (const issue of issues) {
                let agreementCount = 1; // self
                for (const other of runs) {
                    if (other === run) continue;
                    const otherIssues = Array.isArray(other.detectedIssuesRaw)
                        ? other.detectedIssuesRaw
                        : (Array.isArray(other.detectedIssues) ? other.detectedIssues : []);
                    if (otherIssues.some(o => issuesMatchAcrossRuns(issue, o))) {
                        agreementCount++;
                    }
                }
                issue.confidence = agreementCount / N;
                if (agreementCount === N) {
                    issue.detectionSource = issue.detectionSource || 'llm';
                }
                summary.issuesAnnotated++;
            }
        }
    }

    return summary;
}

function scoreCase(detected, expected, code) {
    const isSecureSample = expected.length === 0;

    const detectedCats = taxonomy.normalizeCategories(detected.map(d => d.type));
    const expectedCats = taxonomy.normalizeCategories(expected.map(e => e.type));
    const intersect = new Set();
    for (const c of detectedCats) if (expectedCats.has(c)) intersect.add(c);
    const truePositives = intersect.size;
    const falsePositives = detectedCats.size - truePositives;
    const falseNegatives = expectedCats.size - truePositives;

    const secureFp = isSecureSample && detected.length > 0 ? 1 : 0;
    const secureTn = isSecureSample && detected.length === 0 ? 1 : 0;

    const codeLines = (code || '').split('\n').length || 1;
    let lineAccHit = 0;
    let lineAccTotal = 0;
    for (const issue of detected) {
        if (typeof issue.startLine === 'number' && typeof issue.endLine === 'number') {
            lineAccTotal++;
            if (issue.startLine >= 1 && issue.startLine <= codeLines &&
                issue.endLine >= 1 && issue.endLine <= codeLines &&
                issue.startLine <= issue.endLine) {
                lineAccHit++;
            }
        }
    }

    return {
        truePositives,
        falsePositives,
        falseNegatives,
        trueNegatives: secureTn,
        secureFalsePositiveCases: secureFp,
        secureTrueNegativeCases: secureTn,
        lineAccuracy: lineAccTotal > 0 ? lineAccHit / lineAccTotal : null
    };
}

function aggregateMetrics(allMetrics) {
    if (allMetrics.length === 0) return null;
    const tp = allMetrics.reduce((s, m) => s + m.truePositives, 0);
    const fp = allMetrics.reduce((s, m) => s + m.falsePositives, 0);
    const fn = allMetrics.reduce((s, m) => s + m.falseNegatives, 0);
    const tn = allMetrics.reduce((s, m) => s + m.trueNegatives, 0);
    const secureFp = allMetrics.reduce((s, m) => s + (m.secureFalsePositiveCases || 0), 0);
    const secureTn = allMetrics.reduce((s, m) => s + (m.secureTrueNegativeCases || 0), 0);
    const precision = tp + fp > 0 ? tp / (tp + fp) : 0;
    const recall = tp + fn > 0 ? tp / (tp + fn) : 0;
    const f1 = precision + recall > 0 ? 2 * precision * recall / (precision + recall) : 0;
    const fpr = secureFp + secureTn > 0 ? secureFp / (secureFp + secureTn) : 0;
    return {
        precision: (precision * 100).toFixed(2),
        recall: (recall * 100).toFixed(2),
        f1Score: (f1 * 100).toFixed(2),
        falsePositiveRate: (fpr * 100).toFixed(2),
        truePositives: tp,
        falsePositives: fp,
        falseNegatives: fn,
        trueNegatives: tn,
        secureFalsePositiveCases: secureFp,
        secureTrueNegativeCases: secureTn
    };
}

function rescoreRun(runObj, threshold, options) {
    const computeConfidence = !(options && options.computeConfidence === false);
    const out = JSON.parse(JSON.stringify(runObj));
    out.rescoring = {
        confidenceThreshold: threshold,
        computeInterRunConfidence: computeConfidence,
        rescoredAt: new Date().toISOString(),
        scriptVersion: 2
    };

    if (!Array.isArray(out.results)) {
        return out;
    }

    let totalAnnotated = 0;
    let totalMultiRunGroups = 0;
    for (const modelResult of out.results) {
        if (!Array.isArray(modelResult.detailedResults)) continue;

        // Step 1: annotate per-issue confidence from inter-run agreement.
        if (computeConfidence) {
            const sum = annotateInterRunConfidence(modelResult.detailedResults);
            modelResult.confidenceFromInterRunAgreement = sum;
            totalAnnotated += sum.issuesAnnotated;
            totalMultiRunGroups += sum.groupsWithMultipleRuns;
        }

        // Step 2: apply confidence gate + recompute metrics.
        const perCase = [];
        for (const dr of modelResult.detailedResults) {
            const source = Array.isArray(dr.detectedIssuesRaw) ? dr.detectedIssuesRaw
                : Array.isArray(dr.detectedIssues) ? dr.detectedIssues : [];
            const kept = applyGate(source, threshold);
            const caseCode = (dr.code !== undefined) ? dr.code : '';
            const metrics = scoreCase(kept, dr.expectedVulnerabilities || [], caseCode);
            dr.detected = kept.length;
            dr.detectedIssues = kept;
            dr.metrics = metrics;
            perCase.push(metrics);
        }
        modelResult.metrics = aggregateMetrics(perCase);
        modelResult.confidenceThreshold = threshold;
    }
    out.rescoring.totalIssuesAnnotated = totalAnnotated;
    out.rescoring.totalMultiRunGroups = totalMultiRunGroups;
    return out;
}

function main() {
    const { inputPath, confidence, out, computeConfidence } = parseArgs(process.argv.slice(2));
    if (!inputPath) {
        console.error('Usage: node rescore-metrics.js <run.json> [--confidence 0.7] [--no-compute-confidence] [--out path]');
        process.exit(2);
    }
    const absIn = path.resolve(inputPath);
    const raw = fs.readFileSync(absIn, 'utf8');
    const runObj = JSON.parse(raw);
    const threshold = Number.isFinite(confidence) ? Math.max(0, Math.min(1, confidence)) : 0;

    const rescored = rescoreRun(runObj, threshold, { computeConfidence });

    const suffix = threshold > 0
        ? `.rescored-conf-${String(threshold).replace('.', '_')}.json`
        : '.rescored.json';
    const defaultOut = absIn.replace(/\.json$/, suffix);
    const outPath = out ? path.resolve(out) : defaultOut;
    fs.writeFileSync(outPath, JSON.stringify(rescored, null, 2));

    // Print a short summary to stdout.
    const annot = rescored.rescoring && rescored.rescoring.totalIssuesAnnotated;
    const groups = rescored.rescoring && rescored.rescoring.totalMultiRunGroups;
    if (computeConfidence && annot != null) {
        console.log(`Inter-run confidence annotated ${annot} issues across ${groups} multi-run test cases.`);
    }
    console.log(`Rescored at threshold ${threshold} → ${outPath}`);
    for (const mr of rescored.results || []) {
        const m = mr.metrics || {};
        console.log(`  ${mr.model} [${mr.promptMode}]  F1=${m.f1Score ?? 'n/a'}% Prec=${m.precision ?? 'n/a'}% Recall=${m.recall ?? 'n/a'}% FPR=${m.falsePositiveRate ?? 'n/a'}%`);
    }
}

if (require.main === module) {
    main();
}

module.exports = {
    rescoreRun,
    applyGate,
    scoreCase,
    aggregateMetrics,
    annotateInterRunConfidence,
    issuesMatchAcrossRuns
};
