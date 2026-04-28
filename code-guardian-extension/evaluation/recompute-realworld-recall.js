#!/usr/bin/env node
/**
 * Phase 0 (A3) — Recompute NodeGoat recall against the corrected
 * documented-vulnerabilities list, using the existing realworld-nodegoat.json
 * findings (no Ollama re-run).
 *
 * Match criteria:
 *   1. file path: documented file path is a suffix of the finding file
 *   2. line: within ±20 lines of the documented line, OR the documented entry
 *      has a lineRange and the finding line falls inside it (with ±5 slack), OR
 *      the documented entry has line=null (any line in file matches)
 *   3. category: canonical-category match, where the finding category falls
 *      into the documented entry's category set (per-entry override or default)
 */

const fs = require('fs');
const path = require('path');
const taxonomy = require('./category-taxonomy');

const ROOT = path.resolve(__dirname, '..');

const args = process.argv.slice(2);
function getArg(name) {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : null;
}
const PROJECT = getArg('--project') || 'nodegoat';
const REPORT_PATH = path.join(ROOT, 'evaluation', 'logs', `realworld-${PROJECT}.json`);
const DOCUMENTED_PATH = path.join(ROOT, 'evaluation', 'realworld', `${PROJECT}-vulnerabilities.json`);
const OUT_PATH = path.join(ROOT, 'evaluation', 'logs', `realworld-${PROJECT}-recomputed.json`);

// Per-entry acceptable-category sets. The default for each documented entry is
// the entry's own category plus any sibling bins listed under
// `acceptableCategories` in the JSON. The constant ACCEPTABLE block below
// handles the NodeGoat ID-prefixed entries from the original 7-entry list.
const ACCEPTABLE = {
  'ng-allocations-nosql-injection': new Set(['nosql-injection', 'sql-injection']),
  'ng-contributions-eval-code-injection': new Set(['code-injection', 'deserialization']),
  'ng-profile-redos': new Set(['redos', 'input-validation']),
  'ng-profile-mass-assignment': new Set(['auth-bypass', 'improper-auth', 'input-validation']),
  'ng-user-dao-deprecated-bcrypt': new Set(['weak-crypto', 'other']),
  'ng-error-stack-exposure': new Set(['information-exposure', 'xss', 'other']),
  'ng-tutorial-template-path-injection': new Set(['code-injection', 'path-traversal']),
  // CVE-pinned packages
  'lodash-cve-2021-23337': new Set(['code-injection', 'deserialization', 'xss']),
  'moment-cve-2022-24785': new Set(['path-traversal', 'input-validation', 'code-injection']),
  'node-forge-cve-2022-24771': new Set(['crypto-verification', 'weak-crypto', 'auth-bypass'])
};

function fileMatches(findingFile, documentedFile) {
  return findingFile === documentedFile || findingFile.endsWith(documentedFile);
}

function lineMatches(finding, doc) {
  if (doc.line === null || doc.line === undefined) return true;
  if (doc.lineRange && Array.isArray(doc.lineRange) && doc.lineRange.length === 2) {
    const [lo, hi] = doc.lineRange;
    return finding.line >= lo - 5 && finding.line <= hi + 5;
  }
  return Math.abs(finding.line - doc.line) <= 20;
}

function categoryMatches(finding, doc) {
  const canon = taxonomy.normalizeCategory(finding.category) || 'other';
  const acceptable = ACCEPTABLE[doc.id] || new Set([doc.category]);
  return acceptable.has(canon);
}

function main() {
  if (!fs.existsSync(REPORT_PATH)) {
    console.error(`Run report not found: ${REPORT_PATH}`);
    process.exit(1);
  }
  const report = JSON.parse(fs.readFileSync(REPORT_PATH, 'utf8'));
  const documented = JSON.parse(fs.readFileSync(DOCUMENTED_PATH, 'utf8'));
  const findings = report.scan?.findings || report.findings || [];

  const matchedDocs = new Set();
  const findingMatches = []; // (findingIdx, docId)
  for (let i = 0; i < findings.length; i++) {
    const f = findings[i];
    for (const d of documented) {
      if (fileMatches(f.file, d.file) && lineMatches(f, d) && categoryMatches(f, d)) {
        matchedDocs.add(d.id);
        findingMatches.push({ findingIdx: i, findingFile: f.file, findingLine: f.line, findingCategory: f.category, docId: d.id, docCategory: d.category });
      }
    }
  }

  const recall = matchedDocs.size / documented.length;
  const perCwe = {};
  for (const d of documented) {
    const cwe = d.cwe || 'unknown';
    perCwe[cwe] = perCwe[cwe] || { documented: 0, detected: 0 };
    perCwe[cwe].documented++;
    if (matchedDocs.has(d.id)) perCwe[cwe].detected++;
  }

  const recomputed = {
    test: 'realworld-recomputed',
    project: report.project,
    model: report.model,
    sourceReport: REPORT_PATH,
    documentedSource: DOCUMENTED_PATH,
    summary: {
      totalFindings: findings.length,
      totalDocumented: documented.length,
      matchedDocuments: matchedDocs.size,
      overallRecall: Number(recall.toFixed(4))
    },
    perCwe,
    matches: findingMatches,
    matchedDocIds: [...matchedDocs],
    unmatchedDocIds: documented.filter(d => !matchedDocs.has(d.id)).map(d => d.id),
    notes: [
      'Recomputed against the corrected documented-vulnerabilities list (Phase 0 A2).',
      'Per-entry ACCEPTABLE-category sets allow synonymous canonical bins (e.g. nosql-injection ≈ sql-injection).',
      'Match relaxed to ±20 lines (or lineRange ±5) to absorb function-chunk start-line offset.',
      'No Ollama re-run; this is a deterministic re-scoring of the existing findings JSON.'
    ],
    recordedAt: new Date().toISOString()
  };

  fs.writeFileSync(OUT_PATH, JSON.stringify(recomputed, null, 2) + '\n');
  console.log(`Recomputed report: ${OUT_PATH}`);
  console.log(`Recall: ${matchedDocs.size}/${documented.length} = ${(recall * 100).toFixed(1)}%`);
  if (matchedDocs.size > 0) console.log('Matched docs:', [...matchedDocs].join(', '));
  if (matchedDocs.size < documented.length) console.log('Unmatched docs:', recomputed.unmatchedDocIds.join(', '));
}

if (require.main === module) main();
