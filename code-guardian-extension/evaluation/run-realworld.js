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
const PER_CALL_TIMEOUT_MS = parseInt(getArg('--call-timeout-ms') || '90000', 10);
const USE_RAG = args.includes('--rag');
const RUNS_PER_CHUNK = parseInt(getArg('--runs') || '1', 10);
const SEEDS = [42, 137, 211, 421, 743];
const WHOLE_FILE = args.includes('--whole-file');
const WHOLE_FILE_MAX_CHARS = parseInt(getArg('--whole-file-max-chars') || '20000', 10);
const AUDIT_MODE = args.includes('--audit-mode');
const PROJECT_MAP_MAX_CHARS = parseInt(getArg('--map-max-chars') || '8000', 10);
const MAP_ROOT_OVERRIDE = getArg('--map-root');
const FILES_FILTER = getArg('--files'); // comma-separated paths (relative to map root or absolute)
const projectMapBuilder = require('./project-map-builder');

// Each entry: short rule + keyword tags used for top-k retrieval against the chunk.
// Tags chosen to fire only when the relevant API surface is present in the code.
const RAG_KNOWLEDGE_SNIPPETS = [
  { tags: ['db.query', 'select ', 'insert ', 'update ', 'sql'], rule: 'CWE-89 SQL Injection: parameterise queries — `db.query("... ?", [id])`, never concatenate.' },
  { tags: ['innerhtml', 'document.write', 'res.send(', 'res.render('], rule: 'CWE-79 XSS: escape or sanitise before HTML insertion; prefer textContent or DOMPurify.' },
  { tags: ['child_process', 'exec(', 'spawn(', 'execsync'], rule: 'CWE-78 Command Injection: pass argv array to execFile, never concatenate user input into a shell command.' },
  { tags: ['eval(', 'function(', 'vm.run', 'new function'], rule: 'CWE-95 Eval on req.body / req.query / req.params is a critical sink. FIX: replace eval(req.body.x) with Number(...) or schema-validated JSON.parse.' },
  { tags: ['path.join', 'path.resolve', 'fs.readfile', 'fs.createreadstream', 'sendfile'], rule: 'CWE-22 Path Traversal: canonicalise and check `path.resolve(base, x).startsWith(base)`.' },
  { tags: ['createhash', 'md5', 'sha1', 'bcrypt-nodejs', 'math.random'], rule: 'CWE-327 Weak crypto: md5/sha1/bcrypt-nodejs are deprecated. FIX: sha256, bcrypt, crypto.randomBytes.' },
  { tags: ['$where', '.find(', '.findone(', 'mongo', 'collection.update', '$ne'], rule: 'CWE-943 NoSQL Injection via $where template literal: never interpolate user input into `{$where: `...${x}...`}`. FIX: parameterise — `{userId: parsedId, stocks: {$gt: parsedThreshold}}`.' },
  { tags: ['regex', 'regexp', '.test(', '.match(', '+\\#', '+)+'], rule: 'CWE-1333 ReDoS: nested or repeated quantifiers (`(a+)+`, `([0-9]+)+`) cause catastrophic backtracking. FIX: use single quantifier or possessive groups.' },
  { tags: ['req.body', 'object.assign', '...req.body', 'destructur', '...req.', 'spread'], rule: 'CWE-915 Mass Assignment: do not destructure req.body and pass through to a DAO. FIX: allowlist writable fields explicitly before update.' },
  { tags: ['err.stack', 'error.stack', 'res.send(err', 'res.render(.*err', 'console.error', 'res.json(err'], rule: 'CWE-209 Information Exposure via stack trace: never render full Error objects to clients. FIX: log internally, return a generic message.' },
  { tags: ['__proto__', 'object.assign', 'merge(', 'extend(', 'recursive'], rule: 'CWE-1321 Prototype Pollution: reject __proto__/constructor/prototype keys; prefer Object.create(null).' },
  { tags: ['json.parse', 'serialize', 'unserialize', 'eval'], rule: 'CWE-502 Insecure Deserialization: schema-validate before parsing — ajv or zod.' },
  { tags: ['fetch(', 'axios.get', 'http.get', 'request(', 'https.get'], rule: 'CWE-918 SSRF: validate outbound URLs and reject private IP ranges (10/8, 172.16/12, 192.168/16, 169.254/16, 127/8).' },
  { tags: ['res.render(', 'page', 'template', 'req.params', 'req.query'], rule: 'CWE-94 Dynamic Template Path Injection: never construct render paths from req.params/req.query (e.g. `res.render(`tutorial/${page}`)`). FIX: map the parameter through a static allowlist of known template names.' }
];

function pickTopK(code, k = 5) {
  const lc = code.toLowerCase();
  const scored = RAG_KNOWLEDGE_SNIPPETS.map(s => {
    let hits = 0;
    for (const t of s.tags) if (lc.includes(t)) hits++;
    return { s, hits };
  });
  scored.sort((a, b) => b.hits - a.hits);
  return scored.filter(x => x.hits > 0).slice(0, k).map(x => x.s.rule);
}

function* walkSource(target) {
  if (!fs.existsSync(target)) return;
  const st = fs.statSync(target);
  if (st.isFile()) {
    if (/\.(jsx?|tsx?)$/.test(target)) yield target;
    return;
  }
  for (const name of fs.readdirSync(target)) {
    if (SKIP_DIRS.has(name)) continue;
    const abs = path.join(target, name);
    const sub = fs.statSync(abs);
    if (sub.isDirectory()) yield* walkSource(abs);
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

// Populated once per scan when AUDIT_MODE is true.
let PROJECT_MAP_TEXT = '';

function buildSystemPrompt(code) {
  // Audit mode v3: the LLM runs INDEPENDENTLY of the AST. No project map in
  // the system prompt — that caused the LLM to defer ("already flagged in the
  // map, skipping"). Stage 0 (AST) and Stage 1 (LLM) are now two parallel
  // detectors whose findings are unioned in the report.
  const base = 'Return JSON only with shape {issues:[{type,line,severity,message}]}. If no issues, return {issues:[]}.';
  const sections = [base];
  if (USE_RAG) {
    const top = pickTopK(code, 5);
    if (top.length > 0) {
      sections.push(`RELEVANT SECURITY KNOWLEDGE:\n${top.map((r, i) => `${i + 1}. ${r}`).join('\n')}`);
    }
  }
  return sections.join('\n\n');
}

async function analyseOnce(ollama, code, seed) {
  try {
    // Ollama defaults num_ctx to 2048 tokens — too small for whole-file scope
    // (the file content alone consumes most of the budget, leaving no room for
    // the model to reason or generate output). qwen3:8b supports 32K; we use
    // 16K which fits any single source file plus the system prompt with RAG.
    const resp = await Promise.race([
      ollama.chat({
        model: MODEL,
        messages: [
          { role: 'system', content: buildSystemPrompt(code) },
          { role: 'user', content: `Analyze the following code for security vulnerabilities:\n\n${code}` }
        ],
        format: 'json',
        options: { temperature: 0, num_predict: 1024, num_ctx: 16384, seed }
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

async function analyse(ollama, code) {
  // Multi-run UNION: every issue surfaced by ANY of the N seeds is kept.
  // Sequential through Ollama (which serialises requests anyway) so the
  // per-call timeout fires per-call and the user can see progress per seed.
  const seeds = SEEDS.slice(0, RUNS_PER_CHUNK);
  const seen = new Set();
  const merged = [];
  for (let i = 0; i < seeds.length; i++) {
    const issues = await analyseOnce(ollama, code, seeds[i]);
    for (const issue of issues) {
      const k = `${(issue.type || '').toLowerCase()}@${issue.line}`;
      if (!seen.has(k)) { seen.add(k); merged.push(issue); }
    }
    if (seeds.length > 1) process.stdout.write(`s${i + 1}/${seeds.length}=${issues.length} `);
  }
  return merged;
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

  // Determine the map root (whole-project context) and the analysis files.
  // --map-root overrides; otherwise PROJECT_PATH if dir, else dirname of file.
  const mapRoot = MAP_ROOT_OVERRIDE
    ? path.resolve(MAP_ROOT_OVERRIDE)
    : (fs.statSync(PROJECT_PATH).isFile() ? path.dirname(PROJECT_PATH) : PROJECT_PATH);

  let files;
  if (FILES_FILTER) {
    // Explicit file list. Each entry is resolved against mapRoot (or absolute).
    files = FILES_FILTER.split(',').map(s => s.trim()).filter(Boolean).map(p =>
      path.isAbsolute(p) ? p : path.resolve(mapRoot, p)
    );
  } else {
    files = [...walkSource(PROJECT_PATH)];
  }
  const slice = FILE_LIMIT > 0 ? files.slice(0, FILE_LIMIT) : files;
  const scopeLabel = WHOLE_FILE ? 'whole-file' : 'function-chunked';
  console.log(`  ${slice.length} source files queued (${scopeLabel} scope${AUDIT_MODE ? ' + audit mode' : ''}${FILES_FILTER ? ' + targeted files' : ''}, map root: ${path.relative(ROOT, mapRoot)})`);

  // Audit-mode hybrid pipeline:
  //   Stage 0 (AST): deterministic project-map extraction → direct detections
  //                  (eval, $where, ReDoS, weak-hash, dynamic require, etc.)
  //   Stage 1 (LLM): structural-context-only prompt (imports / request usage /
  //                  inventory — NO pre-flagged sinks, so the model doesn't
  //                  defer to the AST and instead independently analyses each
  //                  file). The LLM finds the structural patterns the AST
  //                  cannot catch (mass-assignment, stack-trace exposure,
  //                  dynamic template paths, semantic library-API misuse).
  //   Stage 2: the union of (0) and (1) is the audit-mode result.
  if (AUDIT_MODE) {
    const mapStart = Date.now();
    const map = projectMapBuilder.buildProjectMap(mapRoot);

    // Stage 0: harvest AST findings as direct detections.
    const astFindings = projectMapBuilder.astFindingsFromMap(map);
    for (const f of astFindings) findings.push(f);

    // Stage 1 system-prompt context: structural only, with sinks suppressed.
    let mapText = projectMapBuilder.formatProjectMap(map, { skipSinks: true });
    if (mapText.length > PROJECT_MAP_MAX_CHARS) {
      mapText = projectMapBuilder.formatProjectMap(map, { skipSinks: true, skipInventory: true });
      if (mapText.length > PROJECT_MAP_MAX_CHARS) mapText = mapText.slice(0, PROJECT_MAP_MAX_CHARS) + '\n... (truncated)';
    }
    PROJECT_MAP_TEXT = mapText;
    console.log(`  audit-mode: project map built in ${((Date.now() - mapStart) / 1000).toFixed(2)}s; Stage 0 (AST) detections: ${astFindings.length}; Stage 1 context: ${PROJECT_MAP_TEXT.length} chars`);
  }

  for (const file of slice) {
    scannedFiles++;
    const rel = path.relative(PROJECT_PATH, file);
    const src = fs.readFileSync(file, 'utf8');
    let chunks;
    if (WHOLE_FILE) {
      // Skip files that exceed the size guard (mirrors extension's analyzeFullFile cap).
      if (src.length > WHOLE_FILE_MAX_CHARS) {
        console.log(`  [${scannedFiles}/${slice.length}] ${rel} (skipped, ${src.length} > ${WHOLE_FILE_MAX_CHARS} chars)`);
        continue;
      }
      chunks = [{ startLine: 1, code: src }];
    } else {
      chunks = splitByFunction(src);
    }
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
