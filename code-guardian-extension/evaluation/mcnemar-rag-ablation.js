#!/usr/bin/env node
'use strict';

/**
 * Per-model McNemar test of RAG vs no-RAG, with Bonferroni correction.
 *
 * Reads a multi-model ablation run JSON, pairs each test case's correctness
 * across LLM-only and LLM+RAG modes for the same model, and reports the
 * McNemar p-value (exact binomial) per model. The Bonferroni-corrected
 * threshold for k tests is alpha_corrected = 0.05 / k.
 *
 * Per-case correctness: a vulnerable case counts as correct if at least one
 * of the 3 runs produced a true-positive AND no false-negative on that run;
 * a secure case counts as correct if all 3 runs produced zero false-positives.
 * This pooled definition matches the inter-run consensus the thesis uses
 * elsewhere (Section eval-r1-confidence).
 *
 * Usage:
 *   node evaluation/mcnemar-rag-ablation.js <run.json>
 */

const fs = require('fs');
const path = require('path');

const ALPHA = 0.05;

function pooledCaseOutcome(caseRuns, isSecure) {
    if (isSecure) {
        // Secure: correct iff every run found zero false-positives.
        return caseRuns.every(r => (r.metrics?.canonical?.falsePositives ?? r.metrics?.falsePositives ?? 0) === 0);
    }
    // Vulnerable: correct iff at least one run produced a TP and no FN.
    return caseRuns.some(r => {
        const m = r.metrics?.canonical || r.metrics || {};
        return (m.truePositives ?? 0) > 0 && (m.falseNegatives ?? 0) === 0;
    });
}

function groupByCase(detailedResults) {
    const map = new Map();
    for (const dr of detailedResults || []) {
        const id = dr.testCaseId;
        if (!map.has(id)) map.set(id, []);
        map.get(id).push(dr);
    }
    return map;
}

// Exact McNemar p-value using the binomial distribution.
function exactMcnemarP(b, c) {
    const n = b + c;
    if (n === 0) return 1.0;
    const k = Math.min(b, c);
    // p = 2 * P(X <= k) where X ~ Binomial(n, 0.5)
    let cum = 0;
    let logCoef = 0;
    for (let i = 0; i < n; i++) logCoef -= Math.log(2); // (1/2)^n contribution split below
    for (let i = 0; i <= k; i++) {
        // C(n, i) * (1/2)^n
        let term = 0;
        for (let j = 1; j <= i; j++) term += Math.log(n - j + 1) - Math.log(j);
        term += -n * Math.log(2);
        cum += Math.exp(term);
    }
    return Math.min(1.0, 2 * cum);
}

function mcnemarForModel(noRagDR, ragDR) {
    const noRagByCase = groupByCase(noRagDR);
    const ragByCase = groupByCase(ragDR);

    const ids = new Set([...noRagByCase.keys(), ...ragByCase.keys()]);
    let bothCorrect = 0;
    let onlyNoRag = 0;
    let onlyRag = 0;
    let bothWrong = 0;

    for (const id of ids) {
        const nr = noRagByCase.get(id) || [];
        const r = ragByCase.get(id) || [];
        if (nr.length === 0 || r.length === 0) continue;
        const isSecure = (nr[0].expectedVulnerabilities || []).length === 0;
        const noRagCorrect = pooledCaseOutcome(nr, isSecure);
        const ragCorrect = pooledCaseOutcome(r, isSecure);
        if (noRagCorrect && ragCorrect) bothCorrect++;
        else if (noRagCorrect && !ragCorrect) onlyNoRag++;
        else if (!noRagCorrect && ragCorrect) onlyRag++;
        else bothWrong++;
    }

    const pValue = exactMcnemarP(onlyNoRag, onlyRag);
    return {
        bothCorrect,
        onlyNoRag,
        onlyRag,
        bothWrong,
        pValue,
        n: bothCorrect + onlyNoRag + onlyRag + bothWrong
    };
}

function main() {
    const inputPath = process.argv[2];
    if (!inputPath) {
        console.error('Usage: node mcnemar-rag-ablation.js <run.json>');
        process.exit(2);
    }
    const r = JSON.parse(fs.readFileSync(path.resolve(inputPath), 'utf8'));

    // Group LLM results by model name.
    const byModel = new Map();
    for (const m of r.results || []) {
        if (m.evaluationFamily && m.evaluationFamily !== 'llm') continue;
        if (!m.promptMode) continue;
        const key = m.requestedModel || m.model;
        if (!byModel.has(key)) byModel.set(key, {});
        byModel.get(key)[m.promptMode] = m;
    }

    const rows = [];
    for (const [model, modes] of byModel.entries()) {
        if (!modes['LLM-only'] || !modes['LLM+RAG']) continue;
        const stats = mcnemarForModel(
            modes['LLM-only'].detailedResults,
            modes['LLM+RAG'].detailedResults
        );
        rows.push({ model, ...stats });
    }

    const k = rows.length;
    const alphaBonf = ALPHA / k;

    console.log(`Run: ${path.relative(process.cwd(), inputPath)}`);
    console.log(`McNemar tests: ${k}`);
    console.log(`Bonferroni alpha = ${ALPHA} / ${k} = ${alphaBonf.toFixed(4)}`);
    console.log('');
    console.log('Model            | n   | both-OK | RAG-only | NR-only | both-wrong | p (exact) | survives 0.05 | survives Bonf');
    console.log('-----------------+-----+---------+----------+---------+------------+-----------+----------------+----------------');
    for (const row of rows) {
        const surv05 = row.pValue < ALPHA ? 'YES' : 'no';
        const survBonf = row.pValue < alphaBonf ? 'YES' : 'no';
        const direction = row.onlyRag > row.onlyNoRag ? '↑' : (row.onlyRag < row.onlyNoRag ? '↓' : '·');
        console.log(`${row.model.padEnd(16)} | ${String(row.n).padStart(3)} | ${String(row.bothCorrect).padStart(7)} | ${String(row.onlyRag).padStart(8)}${direction}| ${String(row.onlyNoRag).padStart(7)} | ${String(row.bothWrong).padStart(10)} | ${row.pValue.toFixed(4).padStart(9)} | ${surv05.padStart(14)} | ${survBonf.padStart(14)}`);
    }
}

main();
