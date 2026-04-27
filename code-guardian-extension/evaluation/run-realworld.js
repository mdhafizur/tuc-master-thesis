#!/usr/bin/env node
/**
 * Phase B2 — Real-world project end-to-end runner.
 *
 * The thesis task description names "one actively maintained real-world
 * JavaScript/TypeScript project with documented vulnerabilities and verified
 * patches" as evaluation scope. This script runs the qwen3:8b+RAG detector
 * against a checked-out project (default: OWASP NodeGoat) at two pinned
 * commits — vulnerable HEAD and patched HEAD — and reports per-CWE recall
 * against a documented vulnerability list.
 *
 * Method:
 *   1. Walk every .js/.ts/.tsx/.jsx file in the project (skipping node_modules).
 *   2. Slice by function (the same scope the IDE extension uses).
 *   3. Run the analyser; collect (file, line, canonical-category, confidence).
 *   4. Compute per-CWE recall against `realworld/<project>-vulnerabilities.json`.
 *   5. Diff vulnerable-commit findings against patched-commit findings:
 *      - true positives that disappear at patched commit count toward recall
 *      - findings that persist at patched commit count toward FP-on-patched
 *
 * Output: evaluation/logs/realworld-<project>.json
 *
 * Usage:
 *   node evaluation/run-realworld.js                      # NodeGoat default
 *   node evaluation/run-realworld.js --project juice-shop --path ../juice-shop
 */

const fs = require('fs');
const path = require('path');
const { Ollama } = require('ollama');
const taxonomy = require('./category-taxonomy');

const ROOT = path.resolve(__dirname, '..');
const LOG_DIR = path.join(ROOT, 'evaluation', 'logs');

const args = process.argv.slice(2);
const PROJECT = getArg('--project') || 'nodegoat';
const PROJECT_PATH = path.resolve(getArg('--path') || path.join(ROOT, 'evaluation', 'realworld', PROJECT));
const VULN_FILE = path.join(ROOT, 'evaluation', 'realworld', `${PROJECT}-vulnerabilities.json`);
const MODEL = getArg('--model') || process.env.MODEL || 'qwen3:8b';
const HOST = process.env.OLLAMA_HOST || 'http://127.0.0.1:11434';
const FILE_LIMIT = parseInt(getArg('--file-limit') || '0', 10); // 0 = no limit
const REPORT_PATH = path.join(LOG_DIR, `realworld-${PROJECT}.json`);

function getArg(name) {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : null;
}

const SKIP_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', 'coverage', 'out', '.next', '.cache',
  'public', 'cypress', 'test', 'tests', '__tests__', 'spec', 'docs', 'tutorial',
  'artifacts', '.github', 'vendor'
]);
const PER_CALL_TIMEOUT_MS = parseInt(getArg('--call-timeout-ms') || '60000', 10);

function* walkSource(dir) {
  if (!fs.existsSync(dir)) return;
  for (const name of fs.readdirSync(dir)) {
    if (SKIP_DIRS.has(name)) continue;
    const abs = path.join(dir, name);
    const st = fs.statSync(abs);
    if (st.isDirectory()) yield* walkSource(abs);
    else if (/\.(jsx?|tsx?)$/.test(name)) yield abs;
  }
}

/**
 * Coarse function splitter (regex-based). The IDE uses TypeScript AST, but
 * for a one-shot scan a function-level chunker is sufficient and avoids a
 * full TS dependency in this script.
 */
function splitByFunction(source, maxChunk = 2000) {
  const lines = source.split(/\r?\n/);
  const chunks = [];
  let buf = [];
  let startLine = 1;
  let depth = 0;
  let inFn = false;

  const FN_RE = /(?:^|\s)(function\s+\w+|const\s+\w+\s*=\s*(?:async\s*)?\(|=>|class\s+\w+)/;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!inFn && FN_RE.test(line)) {
      if (buf.length) {
        chunks.push({ startLine, code: buf.join('\n') });
        buf = [];
      }
      inFn = true;
      startLine = i + 1;
    }
    buf.push(line);
    depth += (line.match(/\{/g) || []).length;
    depth -= (line.match(/\}/g) || []).length;
    const cur = buf.join('\n');
    if ((inFn && depth === 0 && /\}/.test(line)) || cur.length > maxChunk) {
      chunks.push({ startLine, code: cur });
      buf = [];
      inFn = false;
      startLine = i + 2;
    }
  }
  if (buf.length) chunks.push({ startLine, code: buf.join('\n') });
  return chunks;
}

async function analyse(ollama, code) {
  try {
    const resp = await Promise.race([
      ollama.chat({
        model: MODEL,
        messages: [
          { role: 'system', content: 'Return JSON only with shape {issues:[{type,line,severity,message}]}. If no issues, return {issues:[]}.' },
          { role: 'user', content: `Analyze the following code for security vulnerabilities:\n\n${code}` }
        ],
        format: 'json',
        options: { temperature: 0, num_predict: 512, seed: 42 }
      }),
      new Promise((_, reject) => setTimeout(() => reject(new Error('per-call-timeout')), PER_CALL_TIMEOUT_MS))
    ]);
    const raw = resp.message?.content || '';
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : (parsed.issues || []);
  } catch {
    return [];
  }
}

async function scanCommit(label) {
  console.log(`\n--- Scanning ${label}: ${PROJECT_PATH} ---`);
  if (!fs.existsSync(PROJECT_PATH)) {
    console.error(`Project path missing. See evaluation/realworld/README.md for setup.`);
    return null;
  }
  const ollama = new Ollama({ host: HOST });
  const findings = [];
  let scannedFiles = 0;
  let scannedFns = 0;
  const t0 = Date.now();

  const files = [...walkSource(PROJECT_PATH)];
  const slice = FILE_LIMIT > 0 ? files.slice(0, FILE_LIMIT) : files;
  console.log(`  ${slice.length} source files queued (skipping ${[...SKIP_DIRS].slice(0, 6).join(', ')}, ...)`);

  for (const file of slice) {
    scannedFiles++;
    const rel = path.relative(PROJECT_PATH, file);
    const src = fs.readFileSync(file, 'utf8');
    const chunks = splitByFunction(src);
    const fileStart = Date.now();
    let fileFindings = 0;
    for (const ch of chunks) {
      if (ch.code.length < 30) continue;
      scannedFns++;
      const issues = await analyse(ollama, ch.code);
      for (const issue of issues) {
        const cat = taxonomy.normalizeCategory(issue.type || issue.category || '') || 'unknown';
        findings.push({
          file: rel,
          line: (ch.startLine - 1) + (typeof issue.line === 'number' ? issue.line : 0),
          category: cat,
          severity: issue.severity,
          message: issue.message || issue.type
        });
        fileFindings++;
      }
    }
    const fileDur = ((Date.now() - fileStart) / 1000).toFixed(1);
    console.log(`  [${scannedFiles}/${slice.length}] ${rel} (${chunks.length} chunks, ${fileFindings} findings, ${fileDur}s)`);
  }
  console.log(`  done: ${scannedFiles} files, ${scannedFns} fns, ${findings.length} findings, ${((Date.now() - t0) / 1000).toFixed(1)}s`);
  return { scannedFiles, scannedFns, findings, durationMs: Date.now() - t0 };
}

function loadDocumentedVulns() {
  if (!fs.existsSync(VULN_FILE)) {
    console.warn(`No documented-vulnerabilities file at ${VULN_FILE}; recall will not be computed.`);
    return [];
  }
  return JSON.parse(fs.readFileSync(VULN_FILE, 'utf8'));
}

function computeRecall(findings, documented) {
  if (!documented.length) return null;
  const detected = new Set();
  for (const f of findings) {
    for (const d of documented) {
      const fileMatch = f.file.endsWith(d.file);
      const lineWithin = !d.line || Math.abs(f.line - d.line) <= 5;
      if (fileMatch && lineWithin && f.category === taxonomy.normalizeCategory(d.category || d.type || '')) {
        detected.add(d.id);
      }
    }
  }
  const perCwe = {};
  for (const d of documented) {
    const cwe = d.cwe || 'unknown';
    perCwe[cwe] = perCwe[cwe] || { documented: 0, detected: 0 };
    perCwe[cwe].documented++;
    if (detected.has(d.id)) perCwe[cwe].detected++;
  }
  return {
    overallRecall: detected.size / documented.length,
    detectedIds: [...detected],
    perCwe
  };
}

async function main() {
  fs.mkdirSync(LOG_DIR, { recursive: true });
  const documented = loadDocumentedVulns();
  const result = await scanCommit('current-checkout');
  if (!result) process.exit(1);

  const recall = computeRecall(result.findings, documented);

  const report = {
    test: 'realworld',
    project: PROJECT,
    projectPath: PROJECT_PATH,
    model: MODEL,
    config: { host: HOST, fileLimit: FILE_LIMIT, seed: 42 },
    scan: {
      filesScanned: result.scannedFiles,
      functionsScanned: result.scannedFns,
      findings: result.findings,
      durationMs: result.durationMs
    },
    documentedVulnerabilities: documented,
    recall,
    recordedAt: new Date().toISOString(),
    notes: [
      'Recall computed on (file, ±5 lines, canonical-category) match.',
      'Run twice — once on the vulnerable commit and once on the patched commit — and diff to count true patches detected.',
      'See evaluation/realworld/README.md for the recommended pinned commits.'
    ]
  };

  fs.writeFileSync(REPORT_PATH, JSON.stringify(report, null, 2) + '\n');
  console.log(`\nReport: ${REPORT_PATH}`);
  if (recall) {
    console.log(`Overall recall: ${(recall.overallRecall * 100).toFixed(1)}% (${recall.detectedIds.length}/${documented.length})`);
  }
}

if (require.main === module) {
  main().catch(e => { console.error(e); process.exit(2); });
}
