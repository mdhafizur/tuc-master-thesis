#!/usr/bin/env node
'use strict';

/**
 * Held-out threshold validation for the inter-run confidence gate.
 *
 * Reads a 3-runs run JSON, applies inter-run confidence annotation, sweeps the
 * gate threshold over a fixed candidate set, and reports F1 / precision /
 * recall / FPR separately on the train (dev) and test splits defined by
 * evaluation/datasets/split-YYYY-MM-DD.json.
 *
 * The threshold is selected on the train split alone; the reported headline
 * comes from applying that selected threshold to the frozen test split. No
 * model re-invocation: the analysis works from stored per-issue findings.
 *
 * Usage:
 *   node evaluation/held-out-threshold.js <run.json> --split <split.json>
 */

const fs = require('fs');
const path = require('path');
const rescore = require('./rescore-metrics');

const CANDIDATE_THRESHOLDS = [0.0, 0.34, 0.67, 1.0];

function parseArgs(argv) {
    let inputPath = null;
    let splitPath = null;
    for (let i = 0; i < argv.length; i++) {
        if (argv[i] === '--split') splitPath = argv[++i];
        else if (!inputPath) inputPath = argv[i];
    }
    return { inputPath, splitPath };
}

function filterToIds(modelResult, idSet) {
    const filtered = JSON.parse(JSON.stringify(modelResult));
    filtered.detailedResults = (modelResult.detailedResults || []).filter(dr => idSet.has(dr.testCaseId));
    return filtered;
}

function summariseMetrics(modelResult, label) {
    const m = modelResult.metrics || {};
    const cases = (modelResult.detailedResults || []).length;
    const runs = cases; // 1 entry per case-run; for split-level reporting we just count entries
    return {
        label,
        cases: runs,
        f1: m.f1Score,
        precision: m.precision,
        recall: m.recall,
        fpr: m.falsePositiveRate,
        tp: m.truePositives,
        fp: m.falsePositives,
        fn: m.falseNegatives,
        tn: m.trueNegatives
    };
}

function main() {
    const { inputPath, splitPath } = parseArgs(process.argv.slice(2));
    if (!inputPath || !splitPath) {
        console.error('Usage: node held-out-threshold.js <run.json> --split <split.json>');
        process.exit(2);
    }

    const runObj = JSON.parse(fs.readFileSync(path.resolve(inputPath), 'utf8'));
    const split = JSON.parse(fs.readFileSync(path.resolve(splitPath), 'utf8'));

    const trainIds = new Set(split.train.ids);
    const testIds = new Set(split.test.ids);

    console.log(`Run:        ${path.relative(process.cwd(), inputPath)}`);
    console.log(`Split:      ${path.relative(process.cwd(), splitPath)} (train ${trainIds.size}, test ${testIds.size})`);
    console.log('');

    const sweepRows = [];
    for (const threshold of CANDIDATE_THRESHOLDS) {
        const rescored = rescore.rescoreRun(runObj, threshold, { computeConfidence: true });
        const modelResult = rescored.results[0];

        const trainOnly = filterToIds(modelResult, trainIds);
        const testOnly = filterToIds(modelResult, testIds);

        // Re-aggregate metrics for the filtered subset by re-running scoreCase
        // through aggregateMetrics on the per-case metrics already populated by
        // rescoreRun.
        const perCaseTrain = trainOnly.detailedResults.map(d => d.metrics);
        const perCaseTest = testOnly.detailedResults.map(d => d.metrics);
        trainOnly.metrics = rescore.aggregateMetrics(perCaseTrain);
        testOnly.metrics = rescore.aggregateMetrics(perCaseTest);

        sweepRows.push({
            threshold,
            train: summariseMetrics(trainOnly, 'train'),
            test: summariseMetrics(testOnly, 'test')
        });
    }

    console.log('Threshold sweep (canonical matcher, 3 runs already pooled in detailedResults):');
    console.log('');
    console.log('Threshold | TRAIN F1   Prec    Rec     FPR    | TEST F1    Prec    Rec     FPR');
    console.log('----------+--------------------------------------+--------------------------------------');
    for (const row of sweepRows) {
        const t = row.train;
        const e = row.test;
        const fmt = (s) => String(s).padStart(6);
        console.log(`  ${row.threshold.toFixed(2)}    | ${fmt(t.f1)}  ${fmt(t.precision)}  ${fmt(t.recall)}  ${fmt(t.fpr)} | ${fmt(e.f1)}  ${fmt(e.precision)}  ${fmt(e.recall)}  ${fmt(e.fpr)}`);
    }

    // Pick best-on-train: maximise F1; tie-break by lower FPR.
    const best = sweepRows.slice().sort((a, b) => {
        const f1A = parseFloat(a.train.f1);
        const f1B = parseFloat(b.train.f1);
        if (f1B !== f1A) return f1B - f1A;
        return parseFloat(a.train.fpr) - parseFloat(b.train.fpr);
    })[0];

    console.log('');
    console.log(`Selected threshold from TRAIN: ${best.threshold} (F1 ${best.train.f1}%, FPR ${best.train.fpr}%)`);
    console.log(`Frozen TEST result at that threshold: F1 ${best.test.f1}%, Prec ${best.test.precision}%, Recall ${best.test.recall}%, FPR ${best.test.fpr}%`);
}

main();
