#!/usr/bin/env node
/**
 * Phase B5 — Reproducibility metric.
 *
 * The thesis task description names "reproducibility" as one of the evaluation
 * metrics. The harness already runs deterministic decoding (temperature 0,
 * fixed seed 42), but we never measured whether that *actually produces*
 * identical output across re-runs. This script does.
 *
 * Method: take a small subset (default 10 cases), run the analyser N times
 * (default 3) with the same seed, and report:
 *
 *   - byteIdentityRate: % cases where every run produced byte-identical raw JSON
 *   - setIdentityRate:  % cases where every run produced the same canonical
 *                       (category, line) issue set
 *
 * setIdentityRate is the more meaningful number — it says "the detector's
 * conclusions are reproducible even if the raw bytes vary slightly". Byte
 * identity is the strict guarantee deterministic decoding promises.
 *
 * Output: evaluation/logs/reproducibility-report.json
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { Ollama } = require('ollama');
const taxonomy = require('./category-taxonomy');

const ROOT = path.resolve(__dirname, '..');
const LOG_DIR = path.join(ROOT, 'evaluation', 'logs');
const DATASET = path.join(ROOT, 'evaluation', 'datasets', 'vulnerability-test-cases.json');
const REPORT_PATH = path.join(LOG_DIR, 'reproducibility-report.json');

const args = process.argv.slice(2);
const CASES = parseInt(getArg('--cases') || '10', 10);
const RUNS = parseInt(getArg('--runs') || '3', 10);
const MODEL = getArg('--model') || process.env.MODEL || 'qwen3:8b';
const SEED = parseInt(getArg('--seed') || '42', 10);
const HOST = process.env.OLLAMA_HOST || 'http://127.0.0.1:11434';

function getArg(name) {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : null;
}

function sha256(s) {
  return crypto.createHash('sha256').update(s).digest('hex');
}

function canonicalIssueSet(issues) {
  // Normalise to (canonical-category, line) tuples and serialise in sorted order.
  // Insensitive to insertion order and to model paraphrase of the same finding.
  const tuples = (issues || []).map(i => {
    const cat = taxonomy.normalizeCategory(i.type || i.category || '') || 'unknown';
    const line = typeof i.line === 'number' ? i.line : (parseInt(i.line, 10) || 0);
    return `${cat}@${line}`;
  });
  return [...new Set(tuples)].sort().join('|');
}

async function analyse(ollama, code) {
  const startTime = Date.now();
  const resp = await ollama.chat({
    model: MODEL,
    messages: [
      { role: 'system', content: 'Return JSON only with shape {issues:[{type,line,severity,message}]}' },
      { role: 'user', content: `Analyze the following code for security vulnerabilities:\n\n${code}` }
    ],
    format: 'json',
    options: { temperature: 0, num_predict: 1024, seed: SEED }
  });
  const elapsedMs = Date.now() - startTime;
  const raw = resp.message?.content || '';
  let issues = [];
  try {
    const parsed = JSON.parse(raw);
    issues = Array.isArray(parsed) ? parsed : (parsed.issues || []);
  } catch {
    // parse failure counts against reproducibility — record empty issue set
  }
  return { rawHash: sha256(raw), issueSetSig: canonicalIssueSet(issues), elapsedMs, parsed: issues.length };
}

async function loadCases() {
  if (!fs.existsSync(DATASET)) throw new Error(`Dataset not found: ${DATASET}`);
  const raw = JSON.parse(fs.readFileSync(DATASET, 'utf8'));
  const all = Array.isArray(raw) ? raw : (raw.cases || raw.testCases || []);
  return all.slice(0, CASES);
}

async function main() {
  fs.mkdirSync(LOG_DIR, { recursive: true });
  const cases = await loadCases();
  const ollama = new Ollama({ host: HOST });

  console.log(`Reproducibility test: ${cases.length} cases × ${RUNS} runs (model=${MODEL}, seed=${SEED}, host=${HOST})`);

  const perCase = [];
  let byteIdenticalCases = 0;
  let setIdenticalCases = 0;
  const allLatencies = [];

  for (let i = 0; i < cases.length; i++) {
    const tc = cases[i];
    process.stdout.write(`[${i + 1}/${cases.length}] ${tc.id || tc.name || 'case'} `);
    const runs = [];
    for (let r = 0; r < RUNS; r++) {
      try {
        const res = await analyse(ollama, tc.code);
        runs.push(res);
        allLatencies.push(res.elapsedMs);
        process.stdout.write('.');
      } catch (e) {
        runs.push({ error: e.message });
        process.stdout.write('x');
      }
    }
    const okRuns = runs.filter(r => !r.error);
    const byteIdent = okRuns.length === RUNS && new Set(okRuns.map(r => r.rawHash)).size === 1;
    const setIdent = okRuns.length === RUNS && new Set(okRuns.map(r => r.issueSetSig)).size === 1;
    if (byteIdent) byteIdenticalCases++;
    if (setIdent) setIdenticalCases++;
    perCase.push({
      id: tc.id || tc.name || `case-${i}`,
      runs: runs.map(r => r.error ? { error: r.error } : { rawHash: r.rawHash, issueSetSig: r.issueSetSig, latencyMs: r.elapsedMs, parsedIssues: r.parsed }),
      byteIdentical: byteIdent,
      setIdentical: setIdent
    });
    console.log(` byte=${byteIdent ? 'Y' : 'N'} set=${setIdent ? 'Y' : 'N'}`);
  }

  const byteIdentityRate = cases.length ? byteIdenticalCases / cases.length : 0;
  const setIdentityRate = cases.length ? setIdenticalCases / cases.length : 0;
  const sortedLat = [...allLatencies].sort((a, b) => a - b);
  const median = sortedLat.length ? sortedLat[Math.floor(sortedLat.length / 2)] : null;

  const report = {
    test: 'reproducibility',
    config: { model: MODEL, seed: SEED, runs: RUNS, cases: cases.length, host: HOST },
    summary: {
      byteIdenticalCases,
      setIdenticalCases,
      totalCases: cases.length,
      byteIdentityRate: Number(byteIdentityRate.toFixed(4)),
      setIdentityRate: Number(setIdentityRate.toFixed(4)),
      medianLatencyMs: median
    },
    perCase,
    recordedAt: new Date().toISOString(),
    notes: [
      'byteIdentityRate: fraction of cases where raw model output bytes were identical across runs.',
      'setIdentityRate: fraction of cases where the canonical (category, line) issue set was identical across runs.',
      'setIdentityRate is the headline metric for reproducibility of detector conclusions.'
    ]
  };

  fs.writeFileSync(REPORT_PATH, JSON.stringify(report, null, 2) + '\n');
  console.log(`\nReport: ${REPORT_PATH}`);
  console.log(`byteIdentityRate=${(byteIdentityRate * 100).toFixed(1)}%  setIdentityRate=${(setIdentityRate * 100).toFixed(1)}%`);
}

if (require.main === module) {
  main().catch(e => {
    console.error(e);
    process.exit(2);
  });
}
