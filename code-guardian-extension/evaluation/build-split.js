#!/usr/bin/env node
'use strict';

/**
 * Deterministic 70/30 split of the curated 101-case vulnerability corpus.
 * Stratified by vulnerable / secure so both splits keep the FPR denominator.
 * Sorted by case id, then assigned via a fixed-seed shuffle so the split is
 * reproducible from this script alone.
 *
 * Usage:
 *   node evaluation/build-split.js [--out evaluation/datasets/split-YYYY-MM-DD.json]
 *
 * The split is pre-registered: this script is committed before any threshold
 * tuning or held-out analysis is run, so the test split has not been touched
 * during configuration tuning.
 */

const fs = require('fs');
const path = require('path');

const SEED = 0x4e6166;          // "Naf" — fixed deterministic seed
const TRAIN_FRACTION = 0.70;
const ROOT = path.resolve(__dirname, '..');
const DATASET_PATH = path.join(ROOT, 'evaluation', 'datasets', 'vulnerability-test-cases.generated.json');

function getOutPath() {
    const idx = process.argv.indexOf('--out');
    if (idx !== -1 && idx < process.argv.length - 1) {
        return process.argv[idx + 1];
    }
    const today = new Date().toISOString().slice(0, 10); // YYYY-MM-DD UTC
    return path.join(ROOT, 'evaluation', 'datasets', `split-${today}.json`);
}

// Mulberry32 — small fixed-seed PRNG. Reproducible across Node versions.
function mulberry32(seed) {
    let a = seed >>> 0;
    return function () {
        a = (a + 0x6D2B79F5) >>> 0;
        let t = a;
        t = Math.imul(t ^ (t >>> 15), t | 1);
        t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
        return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
}

function shuffle(arr, rng) {
    const a = arr.slice();
    for (let i = a.length - 1; i > 0; i--) {
        const j = Math.floor(rng() * (i + 1));
        [a[i], a[j]] = [a[j], a[i]];
    }
    return a;
}

function main() {
    const dataset = JSON.parse(fs.readFileSync(DATASET_PATH, 'utf8'));
    const cases = dataset.testCases || dataset;

    const vulnerable = [];
    const secure = [];
    for (const c of cases) {
        const expected = (c.expectedVulnerabilities || []).length;
        if (expected > 0) vulnerable.push(c.id);
        else secure.push(c.id);
    }

    vulnerable.sort();
    secure.sort();

    const rng = mulberry32(SEED);
    const vulnShuffled = shuffle(vulnerable, rng);
    const secureShuffled = shuffle(secure, rng);

    const vulnTrainCount = Math.round(vulnShuffled.length * TRAIN_FRACTION);
    const secureTrainCount = Math.round(secureShuffled.length * TRAIN_FRACTION);

    const trainIds = [...vulnShuffled.slice(0, vulnTrainCount), ...secureShuffled.slice(0, secureTrainCount)].sort();
    const testIds = [...vulnShuffled.slice(vulnTrainCount), ...secureShuffled.slice(secureTrainCount)].sort();

    const split = {
        version: '1.0.0',
        createdAt: new Date().toISOString(),
        seed: SEED,
        stratifiedBy: 'vulnerable_or_secure',
        trainFraction: TRAIN_FRACTION,
        sourceDataset: path.relative(ROOT, DATASET_PATH),
        sourceTotalCases: cases.length,
        train: {
            count: trainIds.length,
            vulnerable: vulnShuffled.slice(0, vulnTrainCount).length,
            secure: secureShuffled.slice(0, secureTrainCount).length,
            ids: trainIds
        },
        test: {
            count: testIds.length,
            vulnerable: vulnShuffled.slice(vulnTrainCount).length,
            secure: secureShuffled.slice(secureTrainCount).length,
            ids: testIds
        },
        purpose: 'Held-out validation of the inter-run confidence threshold (Section eval-r1-confidence). The threshold is tuned on `train` only; reported headline numbers under the chosen threshold come from `test`.'
    };

    const outPath = getOutPath();
    fs.writeFileSync(outPath, JSON.stringify(split, null, 2));
    console.log(`Wrote split to ${outPath}`);
    console.log(`  train: ${split.train.count} (${split.train.vulnerable} vuln + ${split.train.secure} secure)`);
    console.log(`  test:  ${split.test.count} (${split.test.vulnerable} vuln + ${split.test.secure} secure)`);
}

main();
